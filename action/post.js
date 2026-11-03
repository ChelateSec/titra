// Titra GitHub Action — post step. Runs when the job ends (always), after every
// other step. It renders the run report into the job summary, uploads it to the
// Titra dashboard when one is configured (which puts the verdict on the PR as a
// Check Run), and fails the check if something was blocked. This post hook is
// what lets Titra be a single `uses:` line with no report step to add.
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");

const env = process.env;
if (env.TITRA_DO_REPORT && env.TITRA_DO_REPORT !== "true") process.exit(0);

const titra = env.TITRA_BIN || "titra";
const report = env.TITRA_REPORT || (env.RUNNER_TEMP || os.tmpdir()) + "/titra-report.md";
const jsonReport = report.replace(/\.md$/, "") + ".json";
const state = env.TITRA_STATE || "";
const failOn = (env.TITRA_FAIL_ON || "block").toLowerCase();

let collected = false; // disable-sudo: root evidence gathered once per post step

main().catch((e) => {
  console.log("titra: post step error: " + e.message);
  process.exit(0); // never fail the job because reporting failed
});

async function main() {
  // 1. Markdown report -> job summary.
  const md = titraRun(["report", "--format", "md", "--out", report]);
  if (md.stdout) process.stdout.write(md.stdout);

  // 2. JSON report -> dashboard.
  titraRun(["report", "--format", "json", "--out", jsonReport]);
  let link = "";
  if (env.TITRA_SERVER && env.TITRA_TOKEN) link = await upload();

  if (env.TITRA_APPROVED_BY) await consumeApproval();

  if (env.GITHUB_STEP_SUMMARY && md.stdout) {
    const head = link ? `**[Open this run in the Titra dashboard](${link})**\n\n` : "";
    try { fs.appendFileSync(env.GITHUB_STEP_SUMMARY, head + md.stdout); } catch (_) {}
  }

  // 3. Set the check result.
  if (failOn === "off" || failOn === "none" || failOn === "") return;
  const gate = titraRun(["report", "--fail-on", failOn]);
  if (gate.status && gate.status !== 0) {
    console.log("::error title=Titra::A dangerous agent action was blocked or flagged. See the job summary for the full report.");
    process.exit(1);
  }
}

// Collecting kernel events needs root; rendering alone does not. Prefer sudo on
// Linux so the trace layer appears, but fall back without it.
function titraRun(args) {
  if (env.TITRA_SUDO_DISABLED === "true") {
    // No general sudo: gather the root-only evidence with the one allowed
    // command, then report as the job user.
    if (!collected) {
      spawnSync("sudo", ["-n", "/usr/local/sbin/titra-root", "collect"], { env, stdio: "ignore" });
      collected = true;
    }
    return spawnSync(titra, args, { env, encoding: "utf8" });
  }
  const useSudo = os.platform() === "linux" && state && fs.existsSync(state);
  const r = useSudo
    ? spawnSync("sudo", ["-E", titra, ...args], { env, encoding: "utf8" })
    : spawnSync(titra, args, { env, encoding: "utf8" });
  if (r.status === null && useSudo) return spawnSync(titra, args, { env, encoding: "utf8" });
  return r;
}

// upload sends the final report to the dashboard and returns the run's link.
async function upload() {
  let story;
  try { story = JSON.parse(fs.readFileSync(jsonReport, "utf8")); } catch (_) { return ""; }
  const body = JSON.stringify({
    head_sha: headSHA(),
    policy_source: env.TITRA_POLICY_SOURCE || "",
    story,
  });
  try {
    const res = await request("POST", env.TITRA_SERVER.replace(/\/+$/, "") + "/api/reports", env.TITRA_TOKEN, body);
    if (res.status !== 200) {
      console.log(`titra: dashboard rejected the report (HTTP ${res.status}): ${res.body.slice(0, 200)}`);
      return "";
    }
    const out = JSON.parse(res.body);
    if (out.policy_drift) console.log("::warning title=Titra::This run did not apply your org's locked Titra policy.");
    console.log("titra: report uploaded — " + out.url);
    return out.url || "";
  } catch (e) {
    console.log("titra: couldn't upload the report: " + e.message);
    return "";
  }
}

// consumeApproval removes the approval label so one approval allows one run.
// Needs issues: write (or pull-requests: write) on the job's token.
async function consumeApproval() {
  const label = env.TITRA_APPROVE_LABEL, num = env.TITRA_APPROVED_NUMBER, tok = env["INPUT_GITHUB-TOKEN"] || env.INPUT_GITHUB_TOKEN;
  if (!label || !num || !tok || !env.GITHUB_REPOSITORY) return;
  const api = (env.GITHUB_API_URL || "https://api.github.com").replace(/\/+$/, "");
  const url = `${api}/repos/${env.GITHUB_REPOSITORY}/issues/${num}/labels/${encodeURIComponent(label)}`;
  try {
    const res = await request("DELETE", url, tok);
    if (res.status === 200 || res.status === 404) console.log(`titra: approval used — removed "${label}" from #${num}.`);
    else console.log(`titra: couldn't remove the approval label (HTTP ${res.status}); remove it by hand so it isn't reused.`);
  } catch (e) {
    console.log("titra: couldn't remove the approval label: " + e.message);
  }
}

// headSHA is the commit the verdict belongs on: the PR head for PR events, the
// pushed commit for pushes. Issue-triggered runs have no commit; they show on
// the dashboard only.
function headSHA() {
  let ev = {};
  try { ev = JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, "utf8")); } catch (_) {}
  if (ev.pull_request && ev.pull_request.head && ev.pull_request.head.sha) return ev.pull_request.head.sha;
  if (["push", "workflow_dispatch", "schedule"].includes(env.GITHUB_EVENT_NAME)) return env.GITHUB_SHA || "";
  return "";
}

function request(method, url, token, body) {
  const u = new URL(url);
  const mod = require(u.protocol === "http:" ? "http" : "https");
  return new Promise((resolve, reject) => {
    const headers = { "User-Agent": "titra-action", Authorization: "Bearer " + token, Accept: "application/vnd.github+json" };
    if (body) { headers["Content-Type"] = "application/json"; headers["Content-Length"] = Buffer.byteLength(body); }
    const req = mod.request(u, { method, headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.setTimeout(15000, () => req.destroy(new Error("timeout")));
    if (body) req.write(body);
    req.end();
  });
}
