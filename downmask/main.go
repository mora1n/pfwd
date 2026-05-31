package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const binaryVersion = "0.1.0"

const (
	protoMagic        uint32 = 0x70667764
	protoVersion      uint8  = 1
	headerSize               = 56
	udpSessionLen            = 16
	udpDefaultPayload        = 1200
	udpMinPayload            = udpSessionLen + 1
	udpMaxPayload            = 65507
	udpMaxRetries            = 3
)

func validateUDPPayloadBytes(payload int) error {
	if payload < udpMinPayload || payload > udpMaxPayload {
		return fmt.Errorf("udp payload 必须位于 %d-%d 字节", udpMinPayload, udpMaxPayload)
	}
	return nil
}

type requestHeader struct {
	Magic       uint32
	Version     uint8
	_pad0       uint8
	_pad1       uint16
	TokenSHA256 [32]byte
	WantedBytes uint64
	SpeedLimit  uint64
}

func (h *requestHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, headerSize)
	binary.BigEndian.PutUint32(buf[0:4], h.Magic)
	buf[4] = h.Version
	copy(buf[8:40], h.TokenSHA256[:])
	binary.BigEndian.PutUint64(buf[40:48], h.WantedBytes)
	binary.BigEndian.PutUint64(buf[48:56], h.SpeedLimit)
	return buf, nil
}

func (h *requestHeader) UnmarshalBinary(buf []byte) error {
	if len(buf) < headerSize {
		return fmt.Errorf("请求头长度不足: %d", len(buf))
	}
	h.Magic = binary.BigEndian.Uint32(buf[0:4])
	h.Version = buf[4]
	copy(h.TokenSHA256[:], buf[8:40])
	h.WantedBytes = binary.BigEndian.Uint64(buf[40:48])
	h.SpeedLimit = binary.BigEndian.Uint64(buf[48:56])
	if h.Magic != protoMagic {
		return fmt.Errorf("magic 不匹配: %x", h.Magic)
	}
	if h.Version != protoVersion {
		return fmt.Errorf("不支持的协议版本: %d", h.Version)
	}
	return nil
}

type seedSource interface {
	ReadRandom(buf []byte) error
}

type memorySeedSource struct {
	seed []byte
}

func newSeedReader(seed []byte) (*memorySeedSource, error) {
	if len(seed) == 0 {
		return nil, errors.New("seed 不能为空")
	}
	return &memorySeedSource{seed: seed}, nil
}

func (r *memorySeedSource) ReadRandom(buf []byte) error {
	size := len(buf)
	if size == 0 {
		return nil
	}
	if size < 0 {
		return fmt.Errorf("无效 slice 大小: %d", size)
	}
	if size >= len(r.seed) {
		return r.readWrapped(buf)
	}
	offset, err := cryptoRandIntn(len(r.seed) - size + 1)
	if err != nil {
		return err
	}
	copy(buf, r.seed[offset:offset+size])
	return nil
}

func (r *memorySeedSource) randomSlice(size int) ([]byte, error) {
	buf := make([]byte, size)
	if err := r.ReadRandom(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (r *memorySeedSource) readWrapped(buf []byte) error {
	pos := 0
	for pos < len(buf) {
		offset, err := cryptoRandIntn(len(r.seed))
		if err != nil {
			return err
		}
		n := copy(buf[pos:], r.seed[offset:])
		pos += n
	}
	return nil
}

type fileSeedSource struct {
	f    *os.File
	size int64
}

func newFileSeedSource(path string) (*fileSeedSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.Size() <= 0 {
		_ = f.Close()
		return nil, errors.New("seed 不能为空")
	}
	return &fileSeedSource{f: f, size: info.Size()}, nil
}

func (r *fileSeedSource) Close() error {
	if r == nil || r.f == nil {
		return nil
	}
	return r.f.Close()
}

func (r *fileSeedSource) ReadRandom(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	if r.size <= 0 {
		return errors.New("seed 不能为空")
	}
	var offset int64
	var err error
	if int64(len(buf)) < r.size {
		offsetLimit := int(r.size - int64(len(buf)) + 1)
		randomOffset, offsetErr := cryptoRandIntn(offsetLimit)
		if offsetErr != nil {
			return offsetErr
		}
		offset = int64(randomOffset)
	} else {
		randomOffset, offsetErr := cryptoRandIntn(int(r.size))
		if offsetErr != nil {
			return offsetErr
		}
		offset = int64(randomOffset)
	}
	pos := 0
	for pos < len(buf) {
		n, readErr := r.f.ReadAt(buf[pos:], offset)
		pos += n
		if pos >= len(buf) {
			return nil
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		offset = 0
	}
	return err
}

func cryptoRandIntn(limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("无效随机上界: %d", limit)
	}
	if limit == 1 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(limit)), nil
}

func tokenDigest(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pfwd-downmask: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("缺少子命令")
	}
	switch args[0] {
	case "pull":
		return runPull(args[1:])
	case "serve":
		return runServe(args[1:])
	case "seed":
		return runSeed(args[1:])
	case "version", "--version", "-v":
		fmt.Println(binaryVersion)
		return nil
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("未知子命令: %s", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `pfwd-downmask - 下行伪装辅助二进制

用法:
  pfwd-downmask pull   --protocol tcp|udp --remote-host HOST(IP) --remote-port PORT --token TOKEN(openssl rand -hex 16) --wanted-bytes N [--speed-limit BPS] [--timeout SEC]
  pfwd-downmask serve  [--tcp-addr HOST:PORT] [--udp-addr HOST:PORT] --token TOKEN(openssl rand -hex 16) [--seed-file PATH] [--max-rate BPS] [--udp-payload-bytes N(17-65507)] [--status-file PATH]
  pfwd-downmask seed   [--path PATH] [--size BYTES]
  pfwd-downmask version`)
}

// ---- 限速辅助 ----

type rateLimiter struct {
	bps    uint64
	last   time.Time
	bucket float64
}

func newRateLimiter(bps uint64) *rateLimiter {
	return &rateLimiter{bps: bps, last: time.Now()}
}

func (r *rateLimiter) wait(n int) {
	if r == nil || r.bps == 0 {
		return
	}
	now := time.Now()
	elapsed := now.Sub(r.last).Seconds()
	r.last = now
	r.bucket += elapsed * float64(r.bps)
	maxBucket := float64(r.bps)
	if r.bucket > maxBucket {
		r.bucket = maxBucket
	}
	r.bucket -= float64(n)
	if r.bucket < 0 {
		sleep := time.Duration(-r.bucket / float64(r.bps) * float64(time.Second))
		time.Sleep(sleep)
		r.last = time.Now()
		r.bucket = 0
	}
}

// ---- pull 子命令 ----

type pullOptions struct {
	Protocol    string
	RemoteHost  string
	RemotePort  int
	LocalIP     string
	Token       string
	WantedBytes uint64
	SpeedLimit  uint64
	Timeout     time.Duration
}

func runPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts pullOptions
	var timeoutSec int
	fs.StringVar(&opts.Protocol, "protocol", "tcp", "tcp|udp")
	fs.StringVar(&opts.RemoteHost, "remote-host", "", "远端主机，建议直填 B 机 IPv4/IPv6")
	fs.IntVar(&opts.RemotePort, "remote-port", 0, "远端端口")
	fs.StringVar(&opts.LocalIP, "local-ip", "", "本地源 IP，可选")
	fs.StringVar(&opts.Token, "token", "", "预共享 token，A/B 两端需一致；可用 openssl rand -hex 16 生成")
	fs.Uint64Var(&opts.WantedBytes, "wanted-bytes", 0, "目标拉流字节")
	fs.Uint64Var(&opts.SpeedLimit, "speed-limit", 0, "限速 bytes/s，0 表示不限")
	fs.IntVar(&timeoutSec, "timeout", 1200, "超时秒数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.Timeout = time.Duration(timeoutSec) * time.Second
	if opts.RemoteHost == "" || opts.RemotePort == 0 {
		return errors.New("--remote-host 和 --remote-port 必填")
	}
	if opts.Token == "" {
		return errors.New("--token 必填")
	}
	if opts.WantedBytes == 0 {
		return errors.New("--wanted-bytes 必须 > 0")
	}

	switch opts.Protocol {
	case "tcp":
		return runPullTCP(&opts)
	case "udp":
		return runPullUDP(&opts)
	default:
		return fmt.Errorf("无效协议: %s", opts.Protocol)
	}
}

type pullResult struct {
	ActualBytes uint64 `json:"actual_bytes"`
	ElapsedMs   int64  `json:"elapsed_ms"`
	Protocol    string `json:"protocol"`
}

func emitPullResult(actual uint64, start time.Time, proto string) error {
	result := pullResult{
		ActualBytes: actual,
		ElapsedMs:   time.Since(start).Milliseconds(),
		Protocol:    proto,
	}
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(&result)
}

func runPullTCP(opts *pullOptions) error {
	addr := net.JoinHostPort(opts.RemoteHost, strconv.Itoa(opts.RemotePort))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if opts.LocalIP != "" {
		localIP := net.ParseIP(opts.LocalIP)
		if localIP == nil {
			return fmt.Errorf("无效 --local-ip: %s", opts.LocalIP)
		}
		raddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return fmt.Errorf("解析地址失败: %w", err)
		}
		tcpLocal, err := localTCPAddr(localIP, raddr)
		if err != nil {
			return err
		}
		dialer.LocalAddr = tcpLocal
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(opts.Timeout)
	_ = conn.SetDeadline(deadline)

	hdr := requestHeader{
		Magic:       protoMagic,
		Version:     protoVersion,
		TokenSHA256: tokenDigest(opts.Token),
		WantedBytes: opts.WantedBytes,
		SpeedLimit:  opts.SpeedLimit,
	}
	hdrBuf, _ := hdr.MarshalBinary()
	if _, err := conn.Write(hdrBuf); err != nil {
		return fmt.Errorf("写请求头失败: %w", err)
	}

	start := time.Now()
	buf := make([]byte, 32*1024)
	var actual uint64
	for actual < opts.WantedBytes {
		toRead := opts.WantedBytes - actual
		if toRead > uint64(len(buf)) {
			toRead = uint64(len(buf))
		}
		n, err := conn.Read(buf[:toRead])
		if n > 0 {
			actual += uint64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
	}
	return emitPullResult(actual, start, "tcp")
}

func runPullUDP(opts *pullOptions) error {
	addr := net.JoinHostPort(opts.RemoteHost, strconv.Itoa(opts.RemotePort))
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("解析地址失败: %w", err)
	}
	var laddr *net.UDPAddr
	if opts.LocalIP != "" {
		localIP := net.ParseIP(opts.LocalIP)
		if localIP == nil {
			return fmt.Errorf("无效 --local-ip: %s", opts.LocalIP)
		}
		laddr, err = localUDPAddr(localIP, raddr)
		if err != nil {
			return err
		}
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return fmt.Errorf("UDP dial 失败: %w", err)
	}
	defer conn.Close()

	var sessionID [udpSessionLen]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return err
	}

	hdr := requestHeader{
		Magic:       protoMagic,
		Version:     protoVersion,
		TokenSHA256: tokenDigest(opts.Token),
		WantedBytes: opts.WantedBytes,
		SpeedLimit:  opts.SpeedLimit,
	}
	hdrBuf, _ := hdr.MarshalBinary()
	requestPkt := append(append([]byte{}, sessionID[:]...), hdrBuf...)

	start := time.Now()
	overallDeadline := start.Add(opts.Timeout)
	var actual uint64
	buf := make([]byte, 65536)

	for attempt := 0; attempt < udpMaxRetries && actual < opts.WantedBytes; attempt++ {
		if _, err := conn.Write(requestPkt); err != nil {
			continue
		}
		idleDeadline := time.Now().Add(5 * time.Second)
		for actual < opts.WantedBytes {
			now := time.Now()
			if now.After(overallDeadline) {
				break
			}
			deadline := overallDeadline
			if idleDeadline.Before(deadline) {
				deadline = idleDeadline
			}
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			if n < udpSessionLen {
				continue
			}
			if string(buf[:udpSessionLen]) != string(sessionID[:]) {
				continue
			}
			payload := uint64(n - udpSessionLen)
			actual += payload
			idleDeadline = time.Now().Add(2 * time.Second)
		}
	}
	return emitPullResult(actual, start, "udp")
}

// ---- serve 子命令 ----

type serveOptions struct {
	TCPAddr    string
	UDPAddr    string
	Token      string
	SeedFile   string
	MaxRate    uint64
	UDPPayload int
	StatusFile string
}

type udpSessionKey struct {
	Addr      string
	SessionID [udpSessionLen]byte
}

type serveStatus struct {
	mu             sync.Mutex
	tcpListening   bool
	udpListening   bool
	bindIP         string
	tcpPort        int
	udpPort        int
	totalBytesSent uint64
	activeSessions int
	udpSessions    map[udpSessionKey]struct{}
}

type serveStatusJSON struct {
	TCPListening   bool   `json:"tcp_listening"`
	UDPListening   bool   `json:"udp_listening"`
	BindIP         string `json:"bind_ip"`
	TCPPort        int    `json:"tcp_port"`
	UDPPort        int    `json:"udp_port"`
	TotalBytesSent uint64 `json:"total_bytes_sent"`
	ActiveSessions int    `json:"active_sessions"`
	UpdatedAt      string `json:"updated_at"`
}

func (s *serveStatus) snapshot() serveStatusJSON {
	s.mu.Lock()
	defer s.mu.Unlock()
	return serveStatusJSON{
		TCPListening:   s.tcpListening,
		UDPListening:   s.udpListening,
		BindIP:         s.bindIP,
		TCPPort:        s.tcpPort,
		UDPPort:        s.udpPort,
		TotalBytesSent: s.totalBytesSent,
		ActiveSessions: s.activeSessions,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts serveOptions
	fs.StringVar(&opts.TCPAddr, "tcp-addr", "", "TCP 监听地址，例 0.0.0.0:5301，空表示不启用")
	fs.StringVar(&opts.UDPAddr, "udp-addr", "", "UDP 监听地址，空表示不启用")
	fs.StringVar(&opts.Token, "token", "", "预共享 token，A/B 两端需一致；可用 openssl rand -hex 16 生成")
	fs.StringVar(&opts.SeedFile, "seed-file", "", "高熵种子文件路径；默认生成路径通常为 /var/lib/pfwd/downmask/seed.bin")
	fs.Uint64Var(&opts.MaxRate, "max-rate", 0, "服务端每会话最大发送速率 bytes/s，0 表示不限")
	fs.IntVar(&opts.UDPPayload, "udp-payload-bytes", udpDefaultPayload, "UDP 单包 payload 字节；必须位于 17-65507")
	fs.StringVar(&opts.StatusFile, "status-file", "", "状态 JSON 文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.Token == "" {
		return errors.New("--token 必填")
	}
	if opts.TCPAddr == "" && opts.UDPAddr == "" {
		return errors.New("必须至少启用 --tcp-addr 或 --udp-addr")
	}
	if err := validateUDPPayloadBytes(opts.UDPPayload); err != nil {
		return fmt.Errorf("--udp-payload-bytes %w", err)
	}

	seed, closeSeed, err := loadOrGenSeed(opts.SeedFile)
	if err != nil {
		return err
	}
	if closeSeed != nil {
		defer closeSeed()
	}

	expected := tokenDigest(opts.Token)
	status := &serveStatus{
		udpSessions: make(map[udpSessionKey]struct{}),
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	stop := make(chan struct{})
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				continue
			}
			close(stop)
			return
		}
	}()

	var wg sync.WaitGroup
	if opts.TCPAddr != "" {
		host, portStr, err := net.SplitHostPort(opts.TCPAddr)
		if err != nil {
			return fmt.Errorf("无效 --tcp-addr: %w", err)
		}
		port, _ := strconv.Atoi(portStr)
		ln, err := net.Listen("tcp", opts.TCPAddr)
		if err != nil {
			return fmt.Errorf("TCP 监听失败 %s: %w", opts.TCPAddr, err)
		}
		status.mu.Lock()
		status.tcpListening = true
		status.bindIP = host
		status.tcpPort = port
		status.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer ln.Close()
			go func() { <-stop; ln.Close() }()
			serveTCPLoop(ln, expected, seed, opts.MaxRate, status)
		}()
	}
	if opts.UDPAddr != "" {
		host, portStr, err := net.SplitHostPort(opts.UDPAddr)
		if err != nil {
			return fmt.Errorf("无效 --udp-addr: %w", err)
		}
		port, _ := strconv.Atoi(portStr)
		pc, err := net.ListenPacket("udp", opts.UDPAddr)
		if err != nil {
			return fmt.Errorf("UDP 监听失败 %s: %w", opts.UDPAddr, err)
		}
		status.mu.Lock()
		status.udpListening = true
		if status.bindIP == "" {
			status.bindIP = host
		}
		status.udpPort = port
		status.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer pc.Close()
			go func() { <-stop; pc.Close() }()
			serveUDPLoop(pc, expected, seed, opts.MaxRate, opts.UDPPayload, status)
		}()
	}

	if opts.StatusFile != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			writeStatusFile(opts.StatusFile, status)
			for {
				select {
				case <-stop:
					writeStatusFile(opts.StatusFile, status)
					return
				case <-ticker.C:
					writeStatusFile(opts.StatusFile, status)
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

func writeStatusFile(path string, s *serveStatus) {
	if path == "" {
		return
	}
	snap := s.snapshot()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&snap); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	f.Close()
	_ = os.Rename(tmp, path)
}

func (s *serveStatus) sessionStart() {
	s.mu.Lock()
	s.activeSessions++
	s.mu.Unlock()
}

func (s *serveStatus) sessionDone() {
	s.mu.Lock()
	s.activeSessions--
	s.mu.Unlock()
}

func (s *serveStatus) addSent(n uint64) {
	atomic.AddUint64(&s.totalBytesSent, n)
}

func (s *serveStatus) tryStartUDPSession(key udpSessionKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.udpSessions[key]; exists {
		return false
	}
	s.udpSessions[key] = struct{}{}
	return true
}

func (s *serveStatus) finishUDPSession(key udpSessionKey) {
	s.mu.Lock()
	delete(s.udpSessions, key)
	s.mu.Unlock()
}

func serveTCPLoop(ln net.Listener, expected [32]byte, seed seedSource, maxRate uint64, status *serveStatus) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleTCPSession(conn, expected, seed, maxRate, status)
	}
}

func handleTCPSession(conn net.Conn, expected [32]byte, seed seedSource, maxRate uint64, status *serveStatus) {
	defer conn.Close()
	status.sessionStart()
	defer status.sessionDone()

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	hdrBuf := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, hdrBuf); err != nil {
		return
	}
	var hdr requestHeader
	if err := hdr.UnmarshalBinary(hdrBuf); err != nil {
		return
	}
	if hdr.TokenSHA256 != expected {
		return
	}
	rate := hdr.SpeedLimit
	if maxRate > 0 && (rate == 0 || rate > maxRate) {
		rate = maxRate
	}
	limiter := newRateLimiter(rate)

	wanted := hdr.WantedBytes
	if wanted == 0 {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	chunk := 32 * 1024
	if uint64(chunk) > wanted {
		chunk = int(wanted)
	}
	buf := make([]byte, chunk)
	var sent uint64
	for sent < wanted {
		toSend := wanted - sent
		if toSend > uint64(chunk) {
			toSend = uint64(chunk)
		}
		slice := buf[:int(toSend)]
		if err := seed.ReadRandom(slice); err != nil {
			return
		}
		limiter.wait(int(toSend))
		_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := conn.Write(slice); err != nil {
			return
		}
		sent += toSend
		status.addSent(toSend)
	}
}

func serveUDPLoop(pc net.PacketConn, expected [32]byte, seed seedSource, maxRate uint64, payload int, status *serveStatus) {
	buf := make([]byte, 1<<16)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < udpSessionLen+headerSize {
			continue
		}
		var sessionID [udpSessionLen]byte
		copy(sessionID[:], buf[:udpSessionLen])
		var hdr requestHeader
		if err := hdr.UnmarshalBinary(buf[udpSessionLen : udpSessionLen+headerSize]); err != nil {
			continue
		}
		if hdr.TokenSHA256 != expected {
			continue
		}
		rate := hdr.SpeedLimit
		if maxRate > 0 && (rate == 0 || rate > maxRate) {
			rate = maxRate
		}
		key := udpSessionKey{
			Addr:      addr.String(),
			SessionID: sessionID,
		}
		if !status.tryStartUDPSession(key) {
			continue
		}
		go handleUDPSession(pc, addr, sessionID, hdr.WantedBytes, rate, seed, payload, key, status)
	}
}

func handleUDPSession(pc net.PacketConn, addr net.Addr, sessionID [udpSessionLen]byte, wanted uint64, rate uint64, seed seedSource, payload int, key udpSessionKey, status *serveStatus) {
	defer status.finishUDPSession(key)
	if wanted == 0 {
		return
	}
	status.sessionStart()
	defer status.sessionDone()

	limiter := newRateLimiter(rate)
	if err := validateUDPPayloadBytes(payload); err != nil {
		return
	}
	var sent uint64
	deadline := time.Now().Add(10 * time.Minute)
	packet := make([]byte, payload)
	copy(packet[:udpSessionLen], sessionID[:])
	for sent < wanted {
		if time.Now().After(deadline) {
			return
		}
		remaining := wanted - sent
		bodySize := payload - udpSessionLen
		if uint64(bodySize) > remaining {
			bodySize = int(remaining)
		}
		packetLen := udpSessionLen + bodySize
		copy(packet[:udpSessionLen], sessionID[:])
		if err := seed.ReadRandom(packet[udpSessionLen:packetLen]); err != nil {
			return
		}
		limiter.wait(packetLen)
		if _, err := pc.WriteTo(packet[:packetLen], addr); err != nil {
			return
		}
		sent += uint64(bodySize)
		status.addSent(uint64(bodySize))
	}
}

func localTCPAddr(localIP net.IP, remote *net.TCPAddr) (*net.TCPAddr, error) {
	if remote == nil {
		return nil, errors.New("缺少远端地址")
	}
	ip, err := ipForFamily(localIP, remote.IP)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip}, nil
}

func localUDPAddr(localIP net.IP, remote *net.UDPAddr) (*net.UDPAddr, error) {
	if remote == nil {
		return nil, errors.New("缺少远端地址")
	}
	ip, err := ipForFamily(localIP, remote.IP)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip}, nil
}

func ipForFamily(localIP, remoteIP net.IP) (net.IP, error) {
	if localIP == nil {
		return nil, errors.New("本地 IP 解析失败")
	}
	if remoteIP == nil {
		return nil, errors.New("远端 IP 解析失败")
	}
	if remoteIP.To4() != nil {
		if localIP.To4() == nil {
			return nil, fmt.Errorf("本地 IP %s 与远端地址族不匹配", localIP.String())
		}
		return localIP.To4(), nil
	}
	if localIP.To4() != nil {
		return nil, fmt.Errorf("本地 IP %s 与远端地址族不匹配", localIP.String())
	}
	ip := localIP.To16()
	if ip == nil {
		return nil, fmt.Errorf("本地 IP %s 无法用于 IPv6", localIP.String())
	}
	return ip, nil
}

func loadOrGenSeed(path string) (seedSource, func() error, error) {
	if path != "" {
		if reader, err := newFileSeedSource(path); err == nil {
			return reader, reader.Close, nil
		}
	}
	buf := make([]byte, 8*1024*1024)
	if _, err := rand.Read(buf); err != nil {
		return nil, nil, err
	}
	reader, err := newSeedReader(buf)
	if err != nil {
		return nil, nil, err
	}
	return reader, nil, nil
}

// ---- seed 子命令 ----

func runSeed(args []string) error {
	if len(args) > 0 && args[0] == "generate" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var path string
	var size int64
	fs.StringVar(&path, "path", "/var/lib/pfwd/downmask/seed.bin", "种子文件路径，默认 /var/lib/pfwd/downmask/seed.bin")
	fs.Int64Var(&size, "size", 1024*1024*1024, "种子文件字节大小；默认 1GB，推荐 256MB-4GB")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if size <= 0 {
		return errors.New("--size 必须 > 0")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}()
	buf := make([]byte, 1024*1024)
	var written int64
	for written < size {
		toWrite := size - written
		if toWrite > int64(len(buf)) {
			toWrite = int64(len(buf))
		}
		if _, err := rand.Read(buf[:toWrite]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:toWrite]); err != nil {
			return err
		}
		written += toWrite
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	hash := sha256.New()
	if data, err := os.ReadFile(path); err == nil {
		hash.Write(data)
	}
	fmt.Printf("seed 已生成: path=%s size=%d sha256=%s\n", path, size, hex.EncodeToString(hash.Sum(nil)))
	return nil
}
