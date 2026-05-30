package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRequestHeaderRoundtrip(t *testing.T) {
	hdr := requestHeader{
		Magic:       protoMagic,
		Version:     protoVersion,
		TokenSHA256: tokenDigest("hello"),
		WantedBytes: 12345,
		SpeedLimit:  6789,
	}
	buf, err := hdr.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(buf) != headerSize {
		t.Fatalf("header size = %d, want %d", len(buf), headerSize)
	}
	var got requestHeader
	if err := got.UnmarshalBinary(buf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != hdr {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, hdr)
	}
}

func TestSeedGenerate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.bin")
	if err := runSeed([]string{"--path", path, "--size", "65536"}); err != nil {
		t.Fatalf("runSeed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 65536 {
		t.Fatalf("size = %d, want 65536", info.Size())
	}
	data, _ := os.ReadFile(path)
	if bytes.Equal(data, make([]byte, 65536)) {
		t.Fatalf("seed file is all zeros")
	}
}

func TestPullIntegration(t *testing.T) {
	testCases := []struct {
		name        string
		protocol    string
		token       string
		serverToken string
		wanted      uint64
		wantActual  uint64
	}{
		{
			name:        "tcp_success",
			protocol:    "tcp",
			token:       "test-token",
			serverToken: "test-token",
			wanted:      131072,
			wantActual:  131072,
		},
		{
			name:        "tcp_bad_token",
			protocol:    "tcp",
			token:       "wrong-token",
			serverToken: "server-token",
			wanted:      1024,
			wantActual:  0,
		},
		{
			name:        "udp_exact_bytes",
			protocol:    "udp",
			token:       "udp-token",
			serverToken: "udp-token",
			wanted:      1500,
			wantActual:  1500,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			seed := make([]byte, 1024*1024)
			for i := range seed {
				seed[i] = byte(i)
			}
			status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}

			var port int
			if tc.protocol == "tcp" {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				defer ln.Close()
				port = ln.Addr().(*net.TCPAddr).Port
				done := make(chan struct{})
				go func() {
					defer close(done)
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					handleTCPSession(conn, tokenDigest(tc.serverToken), seed, 0, status)
				}()
				defer func() { <-done }()
			} else {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen packet: %v", err)
				}
				defer pc.Close()
				port = pc.LocalAddr().(*net.UDPAddr).Port
				go serveUDPLoop(pc, tokenDigest(tc.serverToken), seed, 0, udpDefaultPayload, status)
			}

			stdout, restore := captureStdout(t)
			defer restore()

			args := []string{
				"--protocol", tc.protocol,
				"--remote-host", "127.0.0.1",
				"--remote-port", strconv.Itoa(port),
				"--token", tc.token,
				"--wanted-bytes", strconv.FormatUint(tc.wanted, 10),
				"--timeout", "3",
			}
			if err := runPull(args); err != nil {
				t.Fatalf("runPull: %v", err)
			}

			var result pullResult
			if err := json.Unmarshal([]byte(strings.TrimSpace(stdout())), &result); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if result.Protocol != tc.protocol {
				t.Fatalf("protocol = %s, want %s", result.Protocol, tc.protocol)
			}
			if result.ActualBytes != tc.wantActual {
				t.Fatalf("actual_bytes = %d, want %d", result.ActualBytes, tc.wantActual)
			}
		})
	}
}

func TestRateLimiterShape(t *testing.T) {
	r := newRateLimiter(1024 * 1024)
	start := time.Now()
	for i := 0; i < 10; i++ {
		r.wait(102400)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("rate limiter too slow: %v", elapsed)
	}
}

func TestLocalAddrHelpers(t *testing.T) {
	t.Run("ipv4_tcp", func(t *testing.T) {
		addr, err := localTCPAddr(net.ParseIP("127.0.0.2"), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80})
		if err != nil {
			t.Fatalf("localTCPAddr: %v", err)
		}
		if got := addr.IP.String(); got != "127.0.0.2" {
			t.Fatalf("addr.IP = %s", got)
		}
	})

	t.Run("family_mismatch", func(t *testing.T) {
		_, err := localUDPAddr(net.ParseIP("127.0.0.2"), &net.UDPAddr{IP: net.ParseIP("::1"), Port: 53})
		if err == nil || !strings.Contains(err.Error(), "地址族不匹配") {
			t.Fatalf("expected family mismatch, got %v", err)
		}
	})
}

func TestWriteStatusFileAndSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	status := &serveStatus{
		tcpListening:   true,
		udpListening:   true,
		bindIP:         "127.0.0.1",
		tcpPort:        1001,
		udpPort:        1002,
		totalBytesSent: 4096,
		activeSessions: 2,
		udpSessions:    make(map[udpSessionKey]struct{}),
	}
	writeStatusFile(path, status)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}
	var snap serveStatusJSON
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if !snap.TCPListening || !snap.UDPListening {
		t.Fatalf("unexpected listening flags: %+v", snap)
	}
	if snap.TotalBytesSent != 4096 || snap.ActiveSessions != 2 {
		t.Fatalf("unexpected counters: %+v", snap)
	}
}

func TestUDPSessionDedupPreventsDuplicateStart(t *testing.T) {
	status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}
	var sessionID [udpSessionLen]byte
	copy(sessionID[:], []byte("dedup-session-01"))
	key := udpSessionKey{Addr: "127.0.0.1:12345", SessionID: sessionID}

	if !status.tryStartUDPSession(key) {
		t.Fatalf("first start should succeed")
	}
	if status.tryStartUDPSession(key) {
		t.Fatalf("duplicate start should be rejected")
	}
	status.finishUDPSession(key)
	if !status.tryStartUDPSession(key) {
		t.Fatalf("start after finish should succeed")
	}
}

func TestHandleUDPSessionExactRemaining(t *testing.T) {
	pc := newRecordingPacketConn()
	status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}
	seed := bytes.Repeat([]byte("a"), 4096)
	var sessionID [udpSessionLen]byte
	copy(sessionID[:], []byte("udp-exact-check1"))
	key := udpSessionKey{Addr: "peer", SessionID: sessionID}
	if !status.tryStartUDPSession(key) {
		t.Fatalf("failed to register UDP session")
	}

	handleUDPSession(pc, dummyAddr("peer"), sessionID, 1500, 0, seed, udpDefaultPayload, key, status)

	totalPayload := 0
	for _, pkt := range pc.packets {
		if len(pkt) < udpSessionLen {
			t.Fatalf("short packet: %d", len(pkt))
		}
		totalPayload += len(pkt) - udpSessionLen
	}
	if totalPayload != 1500 {
		t.Fatalf("payload = %d, want 1500", totalPayload)
	}
}

type recordingPacketConn struct {
	mu      sync.Mutex
	packets [][]byte
}

func newRecordingPacketConn() *recordingPacketConn {
	return &recordingPacketConn{}
}

func (r *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (r *recordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := append([]byte(nil), p...)
	r.packets = append(r.packets, cp)
	return len(p), nil
}

func (r *recordingPacketConn) Close() error                     { return nil }
func (r *recordingPacketConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (r *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (r *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (r *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "udp" }
func (d dummyAddr) String() string  { return string(d) }

func captureStdout(t *testing.T) (func() string, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- string(buf)
	}()
	get := func() string {
		w.Close()
		os.Stdout = orig
		return <-done
	}
	restore := func() {
		os.Stdout = orig
	}
	return get, restore
}
