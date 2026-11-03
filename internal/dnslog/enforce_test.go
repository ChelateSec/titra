package dnslog

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func query(name string, id uint16) []byte {
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[0:], id)
	m[2] = 0x01 // RD
	binary.BigEndian.PutUint16(m[4:], 1)
	for _, l := range splitDots(name) {
		m = append(m, byte(len(l)))
		m = append(m, l...)
	}
	return append(m, 0, 0, 1, 0, 1)
}

func freePort(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

// fakeUpstream answers every query with one A record and counts queries.
func fakeUpstream(t *testing.T, hits *int32) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		for {
			buf := make([]byte, 512)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt32(hits, 1)
			e, _ := ParseResponse(buf[:n])
			resp := buildResp(e.Name, [4]byte{140, 82, 112, 3})
			copy(resp[0:2], buf[0:2])
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func ask(t *testing.T, server, name string) Entry {
	t.Helper()
	c, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	q := query(name, 0xbeef)
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer for %s: %v", name, err)
	}
	if binary.BigEndian.Uint16(buf[0:2]) != 0xbeef {
		t.Fatal("answer must keep the query ID")
	}
	e, err := ParseResponse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEnforceRefusesWithoutForwarding(t *testing.T) {
	var hits int32
	var opened atomic.Value
	up := fakeUpstream(t, &hits)
	listen := freePort(t)
	srv := &Server{
		Listen: listen, Upstream: up, LogPath: filepath.Join(t.TempDir(), "dns.jsonl"), Enforce: true,
		Allow: func(n string) bool { return n == "api.github.com" },
		OnAnswer: func(name string, ips []string) {
			time.Sleep(50 * time.Millisecond) // the client must not get the answer before this returns
			opened.Store(name + "=" + ips[0])
		},
	}
	go func() { _ = srv.Run(nil) }()
	time.Sleep(100 * time.Millisecond)

	bad := ask(t, listen, "attacker.example")
	if bad.Rcode != "NXDOMAIN" || len(bad.IPs) != 0 {
		t.Fatalf("denied name should get NXDOMAIN: %+v", bad)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("a denied name must never be forwarded upstream (that alone could leak data)")
	}
	good := ask(t, listen, "api.github.com")
	if good.Rcode != "NOERROR" || len(good.IPs) != 1 {
		t.Fatalf("allowed name should resolve: %+v", good)
	}
	if v, _ := opened.Load().(string); v != "api.github.com=140.82.112.3" {
		t.Fatalf("firewall must be opened before the client gets the answer, got %q", v)
	}
	log := ReadLog(srv.LogPath)
	if len(log) != 2 || !log[0].Denied || log[1].Denied {
		t.Fatalf("log: %+v", log)
	}
}

func TestAuditForwardsButMarks(t *testing.T) {
	var hits int32
	up := fakeUpstream(t, &hits)
	listen := freePort(t)
	srv := &Server{Listen: listen, Upstream: up, LogPath: filepath.Join(t.TempDir(), "dns.jsonl"),
		Allow: func(n string) bool { return false }}
	go func() { _ = srv.Run(nil) }()
	time.Sleep(100 * time.Millisecond)
	if e := ask(t, listen, "attacker.example"); e.Rcode != "NOERROR" {
		t.Fatalf("audit mode resolves everything: %+v", e)
	}
	time.Sleep(50 * time.Millisecond)
	if log := ReadLog(srv.LogPath); len(log) != 1 || !log[0].Denied {
		t.Fatalf("audit mode marks the name: %+v", log)
	}
}

func TestNXDomainFromGarbage(t *testing.T) {
	for _, q := range [][]byte{nil, {1, 2, 3}, make([]byte, 12), append(make([]byte, 12), 63)} {
		if _, err := NXDomain(q); err == nil {
			t.Fatalf("garbage query %v should error, not panic", q)
		}
	}
}
