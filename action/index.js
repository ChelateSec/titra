// Titra GitHub Action — main entry. Builds the guard from the action's own
// checkout, starts whole-job tracing (best effort), and installs the command
// shims onto PATH for the rest of the job. The report runs automatically in
// post.js when the job ends.
//
// Zero npm dependencies on purpose: a security tool should add as little
// untrusted code to your pipeline as possible. We talk to the runner only
// through the files GitHub documents (GITHUB_ENV, GITHUB_PATH, GITHUB_OUTPUT)
// and the ::workflow:: command protocol on stdout.
const { execFileSync, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// The runner exposes inputs as INPUT_<NAME> with spaces turned into "_" but
// hyphens kept (INPUT_FAIL-ON). Accept the underscore form too, for local runs.
const inp = (name, def = "") => {
  const key = "INPUT_" + name.toUpperCase().replace(/ /g, "_");
  const v = process.env[key] ?? process.env[key.replace(/-/g, "_")];
  return (v ?? def).trim();
};

const env = process.env;
const RUNNER_TEMP = env.RUNNER_TEMP || os.tmpdir();
const ACTION_PATH = env.GITHUB_ACTION_PATH || __dirname.replace(/\/action$/, "");

function setEnv(k, v) { if (env.GITHUB_ENV) fs.appendFileSync(env.GITHUB_ENV, `${k}=${v}\n`); env[k] = v; }
function addPath(d) { if (env.GITHUB_PATH) fs.appendFileSync(env.GITHUB_PATH, d + "\n"); }
function setOut(k, v) { if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, `${k}=${v}\n`); }
function group(name, fn) { console.log("::group::" + name); try { return fn(); } finally { console.log("::endgroup::"); } }
function notice(m) { console.log("titra: " + m); }

main().catch((e) => {
  console.log(`::error title=Titra::failed to start: ${e.message}`);
  process.exit(1);
});

async function main() {
  const binDir = path.join(RUNNER_TEMP, "titra");
  const stateDir = path.join(RUNNER_TEMP, "titra-trace");
  const log = path.join(RUNNER_TEMP, "titra-actions.jsonl");
  const report = path.join(RUNNER_TEMP, "titra-report.md");
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(log, "");

  const titra = path.join(binDir, "titra");
  const goVersion = inp("go-version", "1.22");

  console.log("::group::Titra — installing the guard");
  // Prefer a prebuilt release binary (fast, no toolchain). Fall back to
  // building from the action's own source if that isn't available.
  if (!(await tryDownloadBinary(titra))) {
    notice("no prebuilt binary for this version; building from source.");
    ensureGo(goVersion);
    run("go", ["build", "-ldflags", "-X main.version=action", "-o", titra, "."], { cwd: ACTION_PATH });
  }
  fs.chmodSync(titra, 0o755);
  console.log("::endgroup::");

  let mode = inp("mode", "monitor");
  const tools = inp("tools");
  const allowed = inp("allowed-domains");
  const doTrace = inp("trace", "true") === "true";
  const dns = inp("dns", "true") === "true";
  const server = inp("server").replace(/\/+$/, "");
  const token = inp("token");
  if (token) console.log("::add-mask::" + token);

  // Policy: an org policy from the dashboard, the repo's own file, or the
  // built-in defaults. A *locked* org policy wins over the repo's policy and
  // mode inputs, so one team can't quietly weaken the guard for its workflow.
  // Maintainer approval: a run started by adding the approval label is watched
  // (monitor mode) instead of blocked, once. GitHub only lets people with
  // triage/write access add labels, so an outsider can't approve themselves.
  const approveLabel = inp("approve-label", "titra:approve");
  const approval = approvalFromEvent(approveLabel);
  if (approval) {
    notice(`approved by @${approval.by} with the "${approveLabel}" label — watching this run, not blocking it.`);
    mode = "monitor";
  }

  let policyPath = inp("policy");
  let policySource = policyPath ? "repo" : "default";
  let lockedMode = false;
  if (server && token) {
    const org = await fetchOrgPolicy(server, token);
    if (org && org.policy) {
      const orgPath = path.join(RUNNER_TEMP, "titra-org-policy.yml");
      fs.writeFileSync(orgPath, org.policy);
      if (org.locked || !policyPath) {
        if (org.locked && policyPath) notice(`org policy is locked; ignoring this workflow's policy input (${policyPath}).`);
        policyPath = orgPath;
        policySource = "org";
      }
      if (org.locked && !approval) {
        lockedMode = true;
        notice("org policy is locked; its mode applies to this job.");
      }
    }
  } else if (server && !token) {
    notice("server is set but token is empty; not connecting to the dashboard.");
  }

  // Share config with post.js and later steps.
  setEnv("TITRA_LOG", log);
  setEnv("TITRA_STATE", stateDir);
  if (!lockedMode) setEnv("TITRA_MODE", mode);
  setEnv("TITRA_BIN", titra);
  setEnv("TITRA_REPORT", report);
  setEnv("TITRA_FAIL_ON", inp("fail-on", "block"));
  setEnv("TITRA_DO_REPORT", inp("report", "true"));
  setEnv("TITRA_POLICY_SOURCE", policySource);
  if (approveLabel) setEnv("TITRA_APPROVE_LABEL", approveLabel);
  if (approval) {
    setEnv("TITRA_APPROVED_BY", approval.by);
    setEnv("TITRA_APPROVED_NUMBER", String(approval.number));
  }
  if (tools) setEnv("TITRA_TOOLS", tools);
  if (allowed) setEnv("TITRA_ALLOWED_DOMAINS", allowed);

  // Egress control: only allowed domains resolve, and every other outbound
  // connection from the job is rejected (enforce) or recorded (monitor). This
  // holds whatever tool makes the connection: curl, Python, a raw IP.
  const egressInput = inp("egress", "off").toLowerCase(); // opt-in
  let egressOn = false;
  if (egressInput !== "off" && os.platform() === "linux") {
    group("Titra — starting egress control", () => {
      const extra = allowed ? allowed.split(",") : [];
      if (server) { try { extra.push(new URL(server).hostname); } catch (_) {} }
      const genv = { ...env, TITRA_POLICY: policyPath || "", TITRA_MODE: lockedMode ? "" : mode };
      const r = spawnSync("sudo", ["-E", titra, "egress", "start", "--state", stateDir,
        "--mode", egressInput === "audit" ? "audit" : "auto", "--allow", extra.join(",")],
        { stdio: "inherit", env: genv });
      egressOn = r.status === 0;
      if (!egressOn) console.log("::warning title=Titra::egress control could not start; network connections from this job are not restricted.");
    });
  } else if (egressInput !== "off") {
    notice("egress control needs a Linux runner; skipped on " + os.platform() + ".");
  }

  // Whole-job tracing — best effort. Never fail the build over it. When egress
  // control runs it already provides the DNS log, so tracing doesn't start one.
  if (doTrace && os.platform() === "linux") {
    group("Titra — starting whole-job tracing", () => {
      ensureAuditd();
      const r = spawnSync("sudo", ["-E", titra, "trace", "start", "--state", stateDir, `--dns=${dns && !egressOn}`, "--lock"],
        { stdio: "inherit", env });
      if (r.status !== 0) notice("tracing unavailable; command-level guarding still active.");
    });
  }

  // Install the command shims and wire them into the job's PATH/env.
  const args = ["install", "--dir", path.join(binDir, "shims"), "--log", log, "--github-env"];
  if (!lockedMode) args.push("--mode", mode);
  if (policyPath) args.push("--policy", policyPath);
  if (tools) args.push("--tools", tools);
  if (server && token) args.push("--server", server, "--token", token);
  run(titra, args, { stdio: ["ignore", "ignore", "inherit"] });

  // Hook the agent itself. Setup steps that run after Titra (actions/setup-node,
  // setup-python, ...) put their own npm/python ahead of Titra's shims on PATH,
  // so the shims alone can be walked around. Claude Code calls this hook before
  // every tool use, whatever PATH says, and a refusal is exit code 2.
  installClaudeHook(titra, {
    TITRA_LOG: log,
    TITRA_POLICY: policyPath || "",
    TITRA_MODE: lockedMode ? "" : mode,
    TITRA_SHIM_DIR: path.join(binDir, "shims"),
    TITRA_RUN_ID: env.GITHUB_RUN_ID || "",
    TITRA_SERVER: server && token ? server : "",
    TITRA_TOKEN: server && token ? token : "",
    TITRA_WORKSPACE: env.GITHUB_WORKSPACE || "",
    TITRA_RUNNER_TEMP: RUNNER_TEMP,
  });

  // disable-sudo: last, once every guard is up. Without sudo nothing later in
  // the job (an agent included) can flush the firewall, stop the resolver or
  // edit Titra's files as root.
  if (inp("disable-sudo", "false") === "true" && os.platform() === "linux") {
    group("Titra — disabling sudo for the rest of the job", () => {
      if (disableSudo(titra, stateDir)) {
        setEnv("TITRA_SUDO_DISABLED", "true");
        notice("sudo disabled for the rest of this job.");
      } else {
        console.log("::warning title=Titra::could not disable sudo; later steps can still become root.");
      }
    });
  }

  addPath(binDir); // expose `titra` for later steps and for post.js
  setOut("log", log);
  setOut("report", report);
  notice(`guarding this job — mode: ${lockedMode ? "set by org policy" : mode}, policy: ${policySource}` +
    (server && token ? `, reporting to ${server}` : ""));
}

// installClaudeHook registers `titra hook claude` as a PreToolUse hook in the
// user-level Claude Code settings. Agent actions (anthropics/claude-code-action
// and claude-code-base-action) merge this file rather than replace it. The
// hook is a small wrapper with Titra's settings baked in, so it works even if
// the agent's environment is trimmed.
function installClaudeHook(titra, vars) {
  try {
    const home = env.HOME || os.homedir();
    const dir = path.join(home, ".claude");
    const file = path.join(dir, "settings.json");
    fs.mkdirSync(dir, { recursive: true });

    const q = (v) => "'" + String(v).replace(/'/g, "'\\''") + "'";
    const lines = ["#!/bin/sh"];
    for (const [k, v] of Object.entries(vars)) if (v) lines.push(`export ${k}=${q(v)}`);
    lines.push(`exec ${q(titra)} hook claude`);
    const wrapper = path.join(path.dirname(titra), "claude-hook.sh");
    fs.writeFileSync(wrapper, lines.join("\n") + "\n", { mode: 0o700 });

    let settings = {};
    try { settings = JSON.parse(fs.readFileSync(file, "utf8")) || {}; } catch (_) {}
    settings.hooks = settings.hooks || {};
    const pre = Array.isArray(settings.hooks.PreToolUse) ? settings.hooks.PreToolUse : [];
    const already = pre.some((m) => (m.hooks || []).some((h) => h.command === wrapper));
    if (!already) pre.push({ matcher: "*", hooks: [{ type: "command", command: wrapper }] });
    settings.hooks.PreToolUse = pre;
    fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    notice("hooked Claude Code: every agent tool call is checked before it runs.");
  } catch (e) {
    notice("couldn't install the Claude Code hook (" + e.message + "); command shims still active.");
  }
}

// disableSudo replaces the job user's sudo rights with a single root-owned,
// argument-free command (`titra-root collect`) that the post step uses to read
// the kernel evidence. Everything that command reads is copied to root-owned
// paths first, so nothing in the job can steer it.
function disableSudo(titra, stateDir) {
  const user = os.userInfo().username;
  const sh = (cmd) => spawnSync("sudo", ["-n", "sh", "-c", cmd], { stdio: ["ignore", "inherit", "inherit"], env }).status === 0;
  const q = (v) => "'" + String(v).replace(/'/g, "'\\''") + "'";
  const rootBin = "/usr/local/sbin/titra-root";
  const rule = `${user} ALL=(root) NOPASSWD: ${rootBin} collect\n`;
  const ok = sh([
    `install -o root -g root -m 0755 ${q(titra)} ${rootBin}`,
    `install -d -o root -g root -m 0755 /etc/titra /var/lib/titra`,
    `for f in trace.json egress.json egress-allow.txt; do [ -f ${q(stateDir)}/$f ] && install -o root -g root -m 0644 ${q(stateDir)}/$f /etc/titra/$f; done; true`,
    `printf %s ${q(rule)} > /etc/titra/sudoers.tmp`,
    `visudo -cf /etc/titra/sudoers.tmp >/dev/null`,
    // Remove every other grant for this user, then install the single rule.
    `for f in /etc/sudoers.d/*; do [ -f "$f" ] && grep -q "^${user}[[:space:]]" "$f" && rm -f "$f"; done; true`,
    `install -o root -g root -m 0440 /etc/titra/sudoers.tmp /etc/sudoers.d/titra-collect`,
    `rm -f /etc/titra/sudoers.tmp`,
  ].join(" && "));
  if (!ok) return false;
  // Prove it: a general sudo must now fail, the collector must still work.
  const general = spawnSync("sudo", ["-n", "true"], { env, stdio: "ignore" }).status;
  const collect = spawnSync("sudo", ["-n", rootBin, "collect"], { env, stdio: "ignore" }).status;
  if (general === 0) notice("sudo still works for this user (another sudoers rule or group grants it).");
  return general !== 0 && collect === 0;
}

// approvalFromEvent returns {by, number} when this run was started by a
// maintainer adding the approval label to an issue or PR.
function approvalFromEvent(label) {
  if (!label || !env.GITHUB_EVENT_PATH) return null;
  let ev;
  try { ev = JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, "utf8")); } catch (_) { return null; }
  if (ev.action !== "labeled" || !ev.label || ev.label.name !== label) return null;
  const subject = ev.issue || ev.pull_request;
  if (!subject || !ev.sender) return null;
  return { by: ev.sender.login, number: subject.number };
}

// ensureAuditd installs the Linux audit tools when the runner lacks them
// (GitHub's Ubuntu images don't ship auditd). Without them whole-job tracing
// can't start. Best effort: a failure here only turns tracing off.
function ensureAuditd() {
  if (spawnSync("sh", ["-c", "command -v auditctl"], { env }).status === 0) return;
  notice("installing auditd for whole-job tracing...");
  const apt = (args) => spawnSync("sudo", ["-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", ...args],
    { stdio: ["ignore", "ignore", "inherit"], env, timeout: 120000 });
  let r = apt(["install", "-y", "-qq", "auditd"]);
  if (r.status !== 0) {
    apt(["update", "-qq"]);
    r = apt(["install", "-y", "-qq", "auditd"]);
  }
  if (r.status !== 0) notice("couldn't install auditd; tracing will be off.");
}

// fetchOrgPolicy asks the dashboard for this org's policy. Fails open: if the
// dashboard is unreachable the job still runs with its local policy.
async function fetchOrgPolicy(server, token) {
  try {
    const res = await request("GET", server + "/api/policy", token);
    if (res.status === 204) return null;
    if (res.status !== 200) {
      notice(`couldn't load the org policy (HTTP ${res.status}); using the local policy.`);
      return null;
    }
    return JSON.parse(res.body);
  } catch (e) {
    notice(`couldn't reach ${server} (${e.message}); using the local policy.`);
    return null;
  }
}

// request makes one HTTP(S) call with node built-ins.
function request(method, url, token, body) {
  const u = new URL(url);
  const mod = require(u.protocol === "http:" ? "http" : "https");
  return new Promise((resolve, reject) => {
    const headers = { "User-Agent": "titra-action", Authorization: "Bearer " + token };
    if (body) { headers["Content-Type"] = "application/json"; headers["Content-Length"] = Buffer.byteLength(body); }
    const req = mod.request(u, { method, headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.setTimeout(10000, () => req.destroy(new Error("timeout")));
    if (body) req.write(body);
    req.end();
  });
}

function run(cmd, args, opts = {}) {
  execFileSync(cmd, args, { stdio: "inherit", env, ...opts });
}

// tryDownloadBinary fetches the release asset matching this action's ref, e.g.
// titra_linux_amd64 from .../releases/download/v1/. Returns true on success.
async function tryDownloadBinary(dest) {
  const repo = env.GITHUB_ACTION_REPOSITORY; // owner/repo of this action
  const ref = env.GITHUB_ACTION_REF;         // v1, v1.2.3, a sha, ...
  if (!repo || !ref) return false;
  const goos = os.platform() === "win32" ? "windows" : os.platform();
  const arch = { x64: "amd64", arm64: "arm64" }[os.arch()];
  if (!arch) return false;
  const asset = `titra_${goos}_${arch}${goos === "windows" ? ".exe" : ""}`;
  const url = `https://github.com/${repo}/releases/download/${ref}/${asset}`;
  try {
    await fetchTo(url, dest);
    notice(`installed prebuilt ${asset} (${ref}).`);
    return true;
  } catch (_) {
    try { fs.unlinkSync(dest); } catch (_) {}
    return false;
  }
}

// fetchTo downloads url to file, following redirects, using only node built-ins.
function fetchTo(url, file, depth = 0) {
  if (depth > 5) throw new Error("too many redirects");
  const https = require("https");
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { "User-Agent": "titra-action" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        fetchTo(res.headers.location, file, depth + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) { res.resume(); reject(new Error("HTTP " + res.statusCode)); return; }
      const out = fs.createWriteStream(file);
      res.pipe(out);
      out.on("finish", () => out.close(resolve));
      out.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(20000, () => req.destroy(new Error("timeout")));
  });
}

// ensureGo makes `go` runnable. If it's already on PATH, done. Otherwise try a
// couple of standard install locations setup-go uses.
function ensureGo(version, binDir) {
  if (spawnSync("go", ["version"], { env }).status === 0) return;
  const candidates = [
    "/usr/local/go/bin",
    path.join(env.HOME || "", "go", "bin"),
    path.join(env.RUNNER_TOOL_CACHE || "", "go", version, "x64", "bin"),
  ];
  for (const c of candidates) {
    if (c && fs.existsSync(path.join(c, "go"))) {
      setEnv("PATH", c + path.delimiter + env.PATH);
      env.PATH = c + path.delimiter + env.PATH;
      if (spawnSync("go", ["version"], { env }).status === 0) return;
    }
  }
  throw new Error("Go toolchain not found. Add `- uses: actions/setup-go@v5` before Titra, or set go-version.");
}
