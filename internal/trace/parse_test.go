package trace

import (
	"strings"
	"testing"
)

func TestParseExec(t *testing.T) {
	log := `type=SYSCALL msg=audit(1792875523.839:16): arch=c000003e syscall=59 success=yes exit=0 ppid=177 pid=197 uid=0 comm="git" exe="/usr/bin/git" key="titra_exec"
type=EXECVE msg=audit(1792875523.839:16): argc=3 a0="git" a1="push" a2="origin"
type=CWD msg=audit(1792875523.839:16): cwd="/home/runner/work/repo"`
	evs := ParseLog(strings.NewReader(log))
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.Kind != "exec" || e.Comm != "git" || e.PID != 197 || e.PPID != 177 {
		t.Fatalf("bad exec event: %+v", e)
	}
	if len(e.Args) != 3 || e.Args[1] != "push" {
		t.Fatalf("bad args: %v", e.Args)
	}
	if e.Cwd != "/home/runner/work/repo" {
		t.Fatalf("bad cwd: %q", e.Cwd)
	}
}

func TestParseConnectIPv4(t *testing.T) {
	// saddr for 1.1.1.1:443 -> fam=2(0200) port=01BB ip=01010101
	log := `type=SYSCALL msg=audit(1792875523.835:15): arch=c000003e syscall=42 success=yes exit=0 ppid=177 pid=196 uid=0 comm="python3" exe="/usr/bin/python3.13" key="titra_net"
type=SOCKADDR msg=audit(1792875523.835:15): saddr=020001BB010101010000000000000000`
	evs := ParseLog(strings.NewReader(log))
	if len(evs) != 1 || evs[0].Kind != "connect" {
		t.Fatalf("want 1 connect, got %+v", evs)
	}
	if evs[0].Addr != "1.1.1.1" || evs[0].Port != 443 {
		t.Fatalf("bad addr: %s:%d", evs[0].Addr, evs[0].Port)
	}
}

func TestParseFileWatch(t *testing.T) {
	log := `type=SYSCALL msg=audit(1792875523.783:13): arch=c000003e syscall=257 success=yes exit=3 ppid=177 pid=195 uid=0 comm="cat" exe="/usr/bin/cat" key="titra_file"
type=PATH msg=audit(1792875523.783:13): item=0 name="/tmp/ws/.git/config" nametype=NORMAL`
	evs := ParseLog(strings.NewReader(log))
	if len(evs) != 1 || evs[0].Kind != "file" {
		t.Fatalf("want 1 file event, got %+v", evs)
	}
	if evs[0].Path != "/tmp/ws/.git/config" {
		t.Fatalf("bad path: %q", evs[0].Path)
	}
}

func TestParseSkipsFailedExec(t *testing.T) {
	log := `type=SYSCALL msg=audit(1.1:1): syscall=59 success=no exit=-2 pid=1 ppid=0 comm="x" exe="/x" key="titra_exec"
type=EXECVE msg=audit(1.1:1): argc=1 a0="x"`
	if evs := ParseLog(strings.NewReader(log)); len(evs) != 0 {
		t.Fatalf("failed exec should be skipped, got %+v", evs)
	}
}
