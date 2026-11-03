package trace

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Event is one thing a process in the job did, as seen by the kernel.
type Event struct {
	Seq     int64     `json:"seq"`
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"` // exec | connect | file
	PID     int       `json:"pid"`
	PPID    int       `json:"ppid"`
	UID     int       `json:"uid"`
	Comm    string    `json:"comm"`
	Exe     string    `json:"exe"`
	Args    []string  `json:"args,omitempty"` // exec
	Cwd     string    `json:"cwd,omitempty"`
	Path    string    `json:"path,omitempty"` // file
	Addr    string    `json:"addr,omitempty"` // connect
	Port    int       `json:"port,omitempty"` // connect
	Success bool      `json:"success"`
}

// raw groups the audit records that share one event serial.
type raw struct {
	ts      time.Time
	seq     int64
	syscall map[string]string
	execve  map[string]string
	cwd     string
	paths   []string
	saddr   string
}

// ParseLog reads an audit.log stream and returns titra-keyed events in order.
func ParseLog(r io.Reader) []Event {
	groups := map[int64]*raw{}
	var order []int64

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, 0x1d); i >= 0 { // ENRICHED format tail
			line = line[:i]
		}
		typ, ts, seq, rest, ok := header(line)
		if !ok {
			continue
		}
		switch typ {
		case "SYSCALL", "EXECVE", "CWD", "PATH", "SOCKADDR":
		default:
			continue
		}
		g := groups[seq]
		if g == nil {
			g = &raw{ts: ts, seq: seq}
			groups[seq] = g
			order = append(order, seq)
		}
		kv := fields(rest)
		switch typ {
		case "SYSCALL":
			g.syscall = kv
		case "EXECVE":
			g.execve = kv
		case "CWD":
			g.cwd = decode(kv["cwd"])
		case "PATH":
			g.paths = append(g.paths, decode(kv["name"]))
		case "SOCKADDR":
			g.saddr = kv["saddr"]
		}
	}

	var out []Event
	for _, seq := range order {
		g := groups[seq]
		if g.syscall == nil {
			continue
		}
		key := decode(g.syscall["key"])
		ev := Event{
			Seq:     g.seq,
			Time:    g.ts,
			PID:     atoi(g.syscall["pid"]),
			PPID:    atoi(g.syscall["ppid"]),
			UID:     atoi(g.syscall["uid"]),
			Comm:    decode(g.syscall["comm"]),
			Exe:     decode(g.syscall["exe"]),
			Cwd:     g.cwd,
			Success: g.syscall["success"] == "yes",
		}
		switch key {
		case KeyExec:
			if !ev.Success {
				continue
			}
			ev.Kind = "exec"
			ev.Args = execArgs(g.execve)
		case KeyNet:
			addr, port, ok := sockaddr(g.saddr)
			if !ok {
				continue
			}
			ev.Kind = "connect"
			ev.Addr, ev.Port = addr, port
		case KeyFile:
			ev.Kind = "file"
			for _, p := range g.paths {
				if p == "" || p == "(null)" {
					continue
				}
				if !filepath.IsAbs(p) && g.cwd != "" {
					p = filepath.Join(g.cwd, p)
				}
				ev.Path = filepath.Clean(p)
			}
			if ev.Path == "" {
				continue
			}
		default:
			continue
		}
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// header splits `type=X msg=audit(1700000000.123:456): rest`.
func header(line string) (typ string, ts time.Time, seq int64, rest string, ok bool) {
	if !strings.HasPrefix(line, "type=") {
		return
	}
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return
	}
	typ = line[5:sp]
	m := strings.Index(line, "msg=audit(")
	if m < 0 {
		return
	}
	end := strings.Index(line[m:], "):")
	if end < 0 {
		return
	}
	inner := line[m+10 : m+end] // 1700000000.123:456
	colon := strings.LastIndexByte(inner, ':')
	if colon < 0 {
		return
	}
	secs, err := strconv.ParseFloat(inner[:colon], 64)
	if err != nil {
		return
	}
	seq, err = strconv.ParseInt(inner[colon+1:], 10, 64)
	if err != nil {
		return
	}
	ts = time.Unix(0, int64(secs*1e9)).UTC()
	rest = strings.TrimSpace(line[m+end+2:])
	return typ, ts, seq, rest, true
}

// fields parses space-separated key=value pairs; quoted values keep spaces.
func fields(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			break
		}
		k := s[:eq]
		s = s[eq+1:]
		var v string
		if strings.HasPrefix(s, `"`) {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				v, s = s, ""
			} else {
				v, s = s[:end+2], s[end+2:]
			}
		} else {
			sp := strings.IndexByte(s, ' ')
			if sp < 0 {
				v, s = s, ""
			} else {
				v, s = s[:sp], s[sp:]
			}
		}
		out[k] = v
	}
	return out
}

// decode turns an audit value into a string: "quoted", hex-encoded, or bare.
func decode(v string) string {
	if v == "" || v == "(null)" || v == "(none)" {
		return ""
	}
	if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) && len(v) >= 2 {
		return v[1 : len(v)-1]
	}
	if len(v)%2 == 0 && isHex(v) {
		if b, err := hex.DecodeString(v); err == nil {
			return strings.ReplaceAll(string(b), "\x00", " ")
		}
	}
	return v
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func execArgs(kv map[string]string) []string {
	if kv == nil {
		return nil
	}
	argc := atoi(kv["argc"])
	if argc > 4096 {
		argc = 4096
	}
	args := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		k := "a" + strconv.Itoa(i)
		if v, ok := kv[k]; ok {
			args = append(args, decode(v))
			continue
		}
		// Long arguments are split: aN_len=…, aN[0]=…, aN[1]=…
		if _, ok := kv[k+"_len"]; ok {
			var b strings.Builder
			for j := 0; ; j++ {
				part, ok := kv[k+"["+strconv.Itoa(j)+"]"]
				if !ok {
					break
				}
				b.WriteString(decode(part))
			}
			args = append(args, b.String())
		}
	}
	return args
}

// sockaddr decodes a hex struct sockaddr for AF_INET / AF_INET6.
func sockaddr(h string) (string, int, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 8 {
		return "", 0, false
	}
	fam := int(b[0]) | int(b[1])<<8
	port := int(b[2])<<8 | int(b[3])
	switch fam {
	case 2: // AF_INET
		return net.IP(b[4:8]).String(), port, true
	case 10: // AF_INET6
		if len(b) < 24 {
			return "", 0, false
		}
		ip := net.IP(b[8:24])
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), port, true
		}
		return ip.String(), port, true
	}
	return "", 0, false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
