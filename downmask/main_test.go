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
	"syscall"
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
	testCases := []struct {
		name     string
		sizeArg  string
		wantSize int64
	}{
		{name: "raw_bytes", sizeArg: "65536", wantSize: 65536},
		{name: "unit_bytes_from_shell", sizeArg: "268435456", wantSize: 268435456},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "seed.bin")
			if err := runSeed([]string{"--path", path, "--size", tc.sizeArg}); err != nil {
				t.Fatalf("runSeed: %v", err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if info.Size() != tc.wantSize {
				t.Fatalf("size = %d, want %d", info.Size(), tc.wantSize)
			}
			if tc.wantSize <= 65536 {
				data, _ := os.ReadFile(path)
				if bytes.Equal(data, make([]byte, len(data))) {
					t.Fatalf("seed file is all zeros")
				}
			}
		})
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
			status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}
			port, cleanup := startPullTestServer(t, tc.protocol, tc.serverToken, newTestSeed(1024*1024), status)
			defer cleanup()

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

func TestUDPPayloadValidation(t *testing.T) {
	t.Run("helper", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload int
			wantErr string
		}{
			{name: "min_ok", payload: udpMinPayload},
			{name: "default_ok", payload: udpDefaultPayload},
			{name: "max_ok", payload: udpMaxPayload},
			{name: "too_small", payload: udpMinPayload - 1, wantErr: "udp payload 必须位于"},
			{name: "too_large", payload: udpMaxPayload + 1, wantErr: "udp payload 必须位于"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := validateUDPPayloadBytes(tc.payload)
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("validateUDPPayloadBytes(%d): %v", tc.payload, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("validateUDPPayloadBytes(%d) = %v, want substring %q", tc.payload, err, tc.wantErr)
				}
			})
		}
	})

	t.Run("run_serve_rejects_invalid_payload", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload int
		}{
			{name: "too_small", payload: udpMinPayload - 1},
			{name: "too_large", payload: udpMaxPayload + 1},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := runServe([]string{
					"--udp-addr", "127.0.0.1:0",
					"--token", "test-token",
					"--udp-payload-bytes", strconv.Itoa(tc.payload),
				})
				if err == nil || !strings.Contains(err.Error(), "--udp-payload-bytes") {
					t.Fatalf("runServe invalid payload error = %v, want udp-payload-bytes error", err)
				}
			})
		}
	})

	t.Run("run_serve_accepts_valid_payload", func(t *testing.T) {
		done := make(chan error, 1)
		go func() {
			done <- runServe([]string{
				"--udp-addr", "127.0.0.1:0",
				"--token", "test-token",
				"--udp-payload-bytes", strconv.Itoa(udpDefaultPayload),
			})
		}()

		time.Sleep(150 * time.Millisecond)
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("send SIGTERM: %v", err)
		}

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("runServe valid payload: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("runServe did not stop after SIGTERM")
		}
	})
}

func TestServeHelpersAndUDPFlow(t *testing.T) {
	t.Run("local_addr_helpers", func(t *testing.T) {
		addr, err := localTCPAddr(net.ParseIP("127.0.0.2"), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80})
		if err != nil {
			t.Fatalf("localTCPAddr: %v", err)
		}
		if got := addr.IP.String(); got != "127.0.0.2" {
			t.Fatalf("addr.IP = %s", got)
		}

		_, err = localUDPAddr(net.ParseIP("127.0.0.2"), &net.UDPAddr{IP: net.ParseIP("::1"), Port: 53})
		if err == nil || !strings.Contains(err.Error(), "地址族不匹配") {
			t.Fatalf("expected family mismatch, got %v", err)
		}
	})

	t.Run("write_status_snapshot", func(t *testing.T) {
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
	})

	t.Run("udp_session_dedup", func(t *testing.T) {
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
	})

	t.Run("handle_udp_session", func(t *testing.T) {
		testCases := []struct {
			name             string
			wanted           uint64
			payload          int
			wantBytes        int
			wantPackets      int
			wantMaxPacketLen int
		}{
			{
				name:             "exact_remaining_default_payload",
				wanted:           1500,
				payload:          udpDefaultPayload,
				wantBytes:        1500,
				wantPackets:      2,
				wantMaxPacketLen: udpDefaultPayload,
			},
			{
				name:             "custom_payload_respected",
				wanted:           2000,
				payload:          600,
				wantBytes:        2000,
				wantPackets:      4,
				wantMaxPacketLen: 600,
			},
			{
				name:             "invalid_payload_skips_send",
				wanted:           1024,
				payload:          udpMinPayload - 1,
				wantBytes:        0,
				wantPackets:      0,
				wantMaxPacketLen: 0,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				pc := newRecordingPacketConn()
				status := &serveStatus{udpSessions: make(map[udpSessionKey]struct{})}
				var sessionID [udpSessionLen]byte
				copy(sessionID[:], []byte("udp-flow-check01"))
				key := udpSessionKey{Addr: "peer", SessionID: sessionID}
				if !status.tryStartUDPSession(key) {
					t.Fatalf("failed to register UDP session")
				}

				handleUDPSession(pc, dummyAddr("peer"), sessionID, tc.wanted, 0, bytes.Repeat([]byte("a"), 4096), tc.payload, key, status)

				totalPayload, maxPacketLen := pc.payloadStats()
				if totalPayload != tc.wantBytes {
					t.Fatalf("payload = %d, want %d", totalPayload, tc.wantBytes)
				}
				if len(pc.packets) != tc.wantPackets {
					t.Fatalf("packets = %d, want %d", len(pc.packets), tc.wantPackets)
				}
				if maxPacketLen != tc.wantMaxPacketLen {
					t.Fatalf("max packet len = %d, want %d", maxPacketLen, tc.wantMaxPacketLen)
				}
			})
		}
	})
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

func newTestSeed(size int) []byte {
	seed := make([]byte, size)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func startPullTestServer(t *testing.T, protocol, serverToken string, seed []byte, status *serveStatus) (int, func()) {
	t.Helper()

	if protocol == "tcp" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			handleTCPSession(conn, tokenDigest(serverToken), seed, 0, status)
		}()
		return ln.Addr().(*net.TCPAddr).Port, func() {
			_ = ln.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("tcp test server did not stop")
			}
		}
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go serveUDPLoop(pc, tokenDigest(serverToken), seed, 0, udpDefaultPayload, status)
	return pc.LocalAddr().(*net.UDPAddr).Port, func() {
		_ = pc.Close()
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

func (r *recordingPacketConn) payloadStats() (totalPayload, maxPacketLen int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pkt := range r.packets {
		if len(pkt) < udpSessionLen {
			continue
		}
		totalPayload += len(pkt) - udpSessionLen
		if len(pkt) > maxPacketLen {
			maxPacketLen = len(pkt)
		}
	}
	return totalPayload, maxPacketLen
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
		_ = w.Close()
		os.Stdout = orig
		return <-done
	}
	restore := func() {
		os.Stdout = orig
	}
	return get, restore
}
