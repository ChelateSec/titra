package dnslog

import (
	"encoding/binary"
	"testing"
)

// buildResp hand-builds a tiny DNS response for name with one A answer.
func buildResp(name string, ip [4]byte) []byte {
	var m []byte
	hdr := make([]byte, 12)
	hdr[2] = 0x81 // QR + RD
	hdr[3] = 0x80 // RA
	binary.BigEndian.PutUint16(hdr[4:], 1)
	binary.BigEndian.PutUint16(hdr[6:], 1)
	m = append(m, hdr...)
	// question
	var q []byte
	for _, label := range splitDots(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	q = append(q, 0, 1, 0, 1) // A, IN
	qStart := len(m)
	m = append(m, q...)
	// answer: pointer to question name
	ans := []byte{0xc0, byte(qStart)}
	ans = append(ans, 0, 1, 0, 1, 0, 0, 0, 60) // A IN TTL
	ans = append(ans, 0, 4, ip[0], ip[1], ip[2], ip[3])
	m = append(m, ans...)
	return m
}

func splitDots(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestParseResponse(t *testing.T) {
	m := buildResp("attacker.example", [4]byte{203, 0, 113, 7})
	e, err := ParseResponse(m)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "attacker.example" {
		t.Fatalf("name = %q", e.Name)
	}
	if e.Type != "A" || e.Rcode != "NOERROR" {
		t.Fatalf("type=%q rcode=%q", e.Type, e.Rcode)
	}
	if len(e.IPs) != 1 || e.IPs[0] != "203.0.113.7" {
		t.Fatalf("ips = %v", e.IPs)
	}
}
