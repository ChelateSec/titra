#!/usr/bin/env bash
# Real egress-control test: two network namespaces, a real firewall, a real
# resolver. "titra-c" plays the CI runner, "titra-s" plays the internet with an
# allowed host (10.99.0.2) and an attacker host (10.99.0.3). The job's commands
# run as an unprivileged user, like the agent on a GitHub runner.
#
#   sudo scripts/egress-netns-test.sh
set -u
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
TITRA=$TMP/titra
go build -o "$TITRA" . || exit 1
fail=0
pass() { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; fail=1; }

cleanup() {
  ip netns pids titra-s 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids titra-c 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del titra-c 2>/dev/null; ip netns del titra-s 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT
cleanup 2>/dev/null; TMP=$(mktemp -d); TITRA=$TMP/titra; go build -o "$TITRA" .

ip netns add titra-c && ip netns add titra-s
ip link add veth-c type veth peer name veth-s
ip link set veth-c netns titra-c && ip link set veth-s netns titra-s
ip -n titra-c addr add 10.99.0.1/24 dev veth-c
ip -n titra-s addr add 10.99.0.2/24 dev veth-s
ip -n titra-s addr add 10.99.0.3/24 dev veth-s
ip -n titra-s addr add 10.99.0.4/24 dev veth-s
ip -n titra-s addr add 10.99.0.5/24 dev veth-s
for ns in titra-c titra-s; do ip -n $ns link set lo up; done
ip -n titra-c link set veth-c up; ip -n titra-s link set veth-s up
sysctl -qw net.netfilter.nf_log_all_netns=1 2>/dev/null

# The "internet": two web servers and an upstream DNS that logs what it's asked.
mkdir -p "$TMP/allowed" "$TMP/evil" "$TMP/pinned" "$TMP/burst"; echo ALLOWED-OK > "$TMP/allowed/index.html"; echo EVIL-GOT-IT > "$TMP/evil/index.html"
echo PINNED-OK > "$TMP/pinned/index.html"; echo BURST-OK > "$TMP/burst/index.html"
ip netns exec titra-s python3 -m http.server 8080 --bind 10.99.0.4 --directory "$TMP/pinned" >/dev/null 2>&1 &
ip netns exec titra-s python3 -m http.server 8080 --bind 10.99.0.5 --directory "$TMP/burst" >/dev/null 2>&1 &
ip netns exec titra-s python3 -m http.server 8080 --bind 10.99.0.2 --directory "$TMP/allowed" >/dev/null 2>&1 &
ip netns exec titra-s python3 -m http.server 8080 --bind 10.99.0.3 --directory "$TMP/evil" >/dev/null 2>&1 &
cat > "$TMP/dns.py" <<'PY'
import socket, struct, sys
table = {"allowed.test": "10.99.0.2", "evil.test": "10.99.0.3", "burst.test": "10.99.0.5"}
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.0.2", 53))
log = open(sys.argv[1], "a", buffering=1)
while True:
    q, a = s.recvfrom(512)
    i, labels = 12, []
    while q[i]:
        labels.append(q[i+1:i+1+q[i]].decode()); i += 1 + q[i]
    name = ".".join(labels); qtype = struct.unpack(">H", q[i+1:i+3])[0]; end = i + 5
    log.write(name + "\n")
    ip = table.get(name)
    hdr = q[:2] + struct.pack(">HHHHH", 0x8180 if ip else 0x8183, 1, 1 if (ip and qtype == 1) else 0, 0, 0)
    body = q[12:end]
    if ip and qtype == 1:
        body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    s.sendto(hdr + body, a)
PY
ip netns exec titra-s python3 "$TMP/dns.py" "$TMP/upstream-queries.log" &
sleep 1

# The "runner": a private /etc (resolv.conf gets rewritten), egress on, block mode.
cat > "$TMP/runner.sh" <<'SH'
set -u
TMP=$1; TITRA=$2
cp -a /etc "$TMP/etc" && mount --bind "$TMP/etc" /etc
printf 'nameserver 10.99.0.2\n' > /etc/resolv.conf
# Like some runner images: a name pinned in /etc/hosts (never reaches DNS), and
# glibc's "resolve" module in nsswitch (would skip resolv.conf).
echo "10.99.0.4 pinned.test" >> /etc/hosts
printf 'passwd: files\nhosts: files resolve [!UNAVAIL=return] dns\n' > /etc/nsswitch.conf
NSS_BEFORE=$(cat /etc/nsswitch.conf)
ST=$TMP/state; mkdir -p "$ST"
"$TITRA" egress start --state "$ST" --mode block --allow allowed.test,pinned.test,burst.test || { echo "egress start failed"; exit 1; }
job() { setpriv --reuid=1500 --regid=1500 --clear-groups -- "$@"; }
r() { echo "RESULT $1 $2"; }

out=$(job curl -s -m 5 http://allowed.test:8080/); r allowed-by-name "$out"
out=$(job curl -s -m 5 http://evil.test:8080/ 2>&1; echo "exit=$?"); r evil-by-name "$out"
out=$(job curl -s -m 5 http://10.99.0.3:8080/ 2>&1; echo "exit=$?"); r evil-by-ip "$out"
out=$(job python3 -c "import socket; s=socket.create_connection(('10.99.0.3',8080),timeout=5); print('CONNECTED')" 2>&1 | tail -1); r evil-python-socket "$out"
out=$(job dig +time=2 +tries=1 @10.99.0.2 evil.test 2>&1 | grep -E "status:|timed out|refused|unreachable" | head -1); r dns-bypass "$out"
out=$(job curl -s -m 5 http://10.99.0.2:8080/ 2>&1); r allowed-ip-after-lookup "$out"
out=$(curl -s -m 5 http://10.99.0.3:8080/ 2>&1); r root-exempt "$out"
out=$(job curl -s -m 5 http://pinned.test:8080/ 2>&1); r pinned-in-hosts "$out"
grep -q resolve /etc/nsswitch.conf && r nss-diverted no || r nss-diverted yes
# Many parallel first lookups of one new name: every one must connect.
for i in 1 2 3 4 5 6 7 8; do job curl -s -m 5 http://burst.test:8080/ > "$TMP/burst.$i" 2>&1 & done; wait
r burst "$(cat "$TMP"/burst.* | sort | uniq -c | tr -s ' ' | tr '\n' ';')"

: > "$ST/empty.jsonl"
"$TITRA" report --log "$ST/empty.jsonl" --state "$ST" --format json --out "$ST/report.json" >/dev/null 2>&1
python3 - "$ST/report.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
print("RESULT report-status", s.get("status"))
print("RESULT report-blocked", ",".join(sorted(r["args"][0] for r in s.get("blocked", []))))
PY
"$TITRA" egress stop --state "$ST" >/dev/null 2>&1
out=$(job curl -s -m 5 http://10.99.0.3:8080/ 2>&1); r after-stop "$out"
[ "$(cat /etc/nsswitch.conf)" = "$NSS_BEFORE" ] && r nss-restored yes || r nss-restored no
SH
results=$(ip netns exec titra-c unshare --mount bash "$TMP/runner.sh" "$TMP" "$TITRA" 2>&1)
echo "$results" | grep -v '^RESULT' | sed 's/^/  | /'
get() { echo "$results" | grep "^RESULT $1 " | cut -d' ' -f3-; }

[ "$(get allowed-by-name)" = "ALLOWED-OK" ] && pass "allowed domain reachable" || bad "allowed domain: $(get allowed-by-name)"
case "$(get evil-by-name)" in *EVIL*) bad "evil.test reached: $(get evil-by-name)";; *) pass "evil.test blocked ($(get evil-by-name | tr '\n' ' '))";; esac
case "$(get evil-by-ip)" in *EVIL*) bad "raw IP reached";; *) pass "raw IP 10.99.0.3 blocked";; esac
case "$(get evil-python-socket)" in *CONNECTED*) bad "python socket connected";; *) pass "python socket blocked ($(get evil-python-socket))";; esac
case "$(get dns-bypass)" in *NOERROR*|*NXDOMAIN*) bad "direct DNS to another server got through: $(get dns-bypass)";; *) pass "DNS to another server blocked ($(get dns-bypass))";; esac
[ "$(get allowed-ip-after-lookup)" = "ALLOWED-OK" ] && pass "allowed host's IP reachable" || bad "allowed IP: $(get allowed-ip-after-lookup)"
grep -qx evil.test "$TMP/upstream-queries.log" && bad "evil.test was forwarded upstream" || pass "evil.test never forwarded upstream"
[ "$(get root-exempt)" = "EVIL-GOT-IT" ] && pass "root is exempt (why disable-sudo exists)" || bad "root: $(get root-exempt)"
[ "$(get report-status)" = "blocked" ] && pass "report status blocked" || bad "report status: $(get report-status)"
case "$(get report-blocked)" in *evil.test*10.99.0.3:8080*|*10.99.0.3:8080*evil.test*) pass "report lists: $(get report-blocked)";; *) bad "report blocked list: $(get report-blocked)";; esac
[ "$(get after-stop)" = "EVIL-GOT-IT" ] && pass "egress stop removes the rules" || bad "after stop: $(get after-stop)"
[ "$(get pinned-in-hosts)" = "PINNED-OK" ] && pass "allowed name pinned in /etc/hosts reachable" || bad "pinned host: $(get pinned-in-hosts)"
[ "$(get nss-diverted)" = "yes" ] && pass "nsswitch 'resolve' bypass removed during the job" || bad "nsswitch still uses resolve"
case "$(get burst)" in " 8 BURST-OK;"|"8 BURST-OK;") pass "8 parallel first lookups all connected";; *) bad "parallel lookups: $(get burst)";; esac
[ "$(get nss-restored)" = "yes" ] && pass "nsswitch restored on stop" || bad "nsswitch not restored"
exit $fail
