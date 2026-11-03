# Titra

**Watch what AI agents do in your CI job — and block the dangerous actions, in real time.**

Titra is [Chelate Sec](https://github.com/ChelateSec)'s runtime guard for agentic CI/CD. Teams drop AI agents (Claude Code, Gemini CLI, Copilot) into their pipelines to triage issues and review PRs. Those agents read whatever a stranger writes and act with the repo's credentials. One prompt-injected issue and the agent pushes code, approves its own PR, or leaks a token — and nobody sees it happen.

Titra is one line in your workflow. It watches the whole job, blocks the actions that turn a prompt injection into a supply-chain compromise, and posts a plain-language report on the run. The block decision is deterministic policy, **never a model** — a guard that asked an LLM whether to block could itself be prompt-injected.

> Securing the agentic CI/CD.

## Quick start

```yaml
      - name: Titra
        uses: ChelateSec/titra@v1
        with:
          mode: monitor      # watch only; switch to enforce when you trust it
```

Put it after `actions/checkout` and before your agent step. That's the whole install: no server, no app, no account. Titra watches the job, and when it ends it posts a report to the run's **Summary** tab by itself. Flip `mode: enforce` to start blocking.

## What it does

Three layers, from one line:

1. **Guards commands.** `git`, `gh`, `curl`, `npm` and friends are intercepted. A push to a protected branch, a self-approved PR, a package publish, a read of `.git/config` — refused before it runs.
2. **Watches the whole job.** Using the Linux kernel's audit subsystem, Titra sees *every* process, outbound connection and credential-file read — even a tool run by absolute path to dodge the shims, or an exfil over a raw socket from Python. Nothing in the job is invisible.
3. **Hooks the agent.** With Claude Code it reads every tool call the agent makes and blocks the dangerous ones at the source, so the report shows the agent's own intent.

The report ties it together into a story:

> `ext-user` (outside contributor) opened issue #42. Claude Code ran with **contents, pull-requests** write access and tried 3 dangerous actions — Titra stopped them before they ran.

...followed by the blocked actions, who triggered the run, the token's permissions, and everything else the job touched (unexpected destinations, stray credential reads, tools run around the guard).

## Network egress control

Opt-in (`egress: on`). On Linux runners Titra can also control where the job connects. Only allowed
domains resolve (GitHub and the Actions service, package registries, the model
APIs agents use, plus anything you add), and a firewall rejects every other
outbound connection from the job: a `curl` to an unknown host, a raw IP, a
Python socket, or a DNS query to another server. This holds even when an agent
or attacker code skips every command guard.

- `mode: enforce` blocks; `mode: monitor` records what would have been blocked.
- Add hosts with the `allowed-domains` input or `allowed_domains` in the policy.
- `egress: on` turns it on, `egress: audit` records without blocking (a good first week), `egress: off` is the default.
- Blocked destinations appear in the report and fail the job like any other block.

Known limits: traffic from Docker containers on a bridge network isn't filtered,
and data can still leave through an allowed service (for example a comment
posted with the job's own GitHub token). Keep the token's permissions minimal.

## Agent write guard

The AI agent may only write inside the repository checkout. Its Write/Edit
tools and shell writes (`>`, `>>`, `tee`, `cp`, `mv`, `sed -i`, `dd`...) are
refused when they target anything else: `$GITHUB_ENV` and `$GITHUB_PATH`
(injection into every later step), shell profiles, other actions' code, Titra's
own files, the agent's settings, or `.git/` and workflow files inside the repo.
Set `writes: any` in the policy to turn it off.

## disable-sudo

GitHub-hosted runners give the job passwordless sudo, so anything in the job
could become root and switch Titra off. With `disable-sudo: true`, Titra
removes that right once its guards are up, leaving only one root-owned,
argument-free command its own post step uses. Leave it off if a later step
needs `sudo`.

## Modes

| Mode | What happens |
| --- | --- |
| `monitor` | Logs everything, blocks nothing. Start here. |
| `dry-run` | Logs and marks what *would* block, still allows it. |
| `enforce` | Blocks matching actions in real time and fails the check. |

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `mode` | `monitor` | `monitor` \| `dry-run` \| `enforce` |
| `policy` | *(built-in)* | Path to a policy file; omit for secure defaults |
| `tools` | *(built-in set)* | Comma-separated tools to guard |
| `egress` | `off` | Network egress control (opt-in): `on`, `audit` (record only) or `off` |
| `disable-sudo` | `false` | Remove sudo for the rest of the job once Titra is up |
| `trace` | `true` | Watch the whole job with the kernel (Linux + sudo) |
| `dns` | `true` | Resolve outbound connections to domain names |
| `allowed-domains` | — | Extra destinations this job is expected to reach |
| `report` | `true` | Post the report and set the check automatically |
| `fail-on` | `block` | Fail on `block`, `any`, or `off` |
| `server` | — | Titra for Organizations dashboard URL (paid, optional) |
| `token` | — | Your org's Titra token: `${{ secrets.TITRA_TOKEN }}` |
| `approve-label` | `titra:approve` | Label a maintainer adds to approve one watched re-run; empty disables |
| `github-token` | `github.token` | Used to remove the approval label after the approved run |

## When a block was a false alarm: maintainer approval

Every blocked run tells maintainers how to allow it. A maintainer adds the
`titra:approve` label to the issue or PR (with Titra for Organizations, also
**Approve & re-run** in the dashboard). The workflow runs once more with Titra *watching* instead of
blocking, the report records who approved it, and Titra removes the label so the
approval can't be reused.

It's safe because GitHub only lets people with triage or write access add
labels. An outsider who opened the issue can't approve their own run.

Your workflow needs the `labeled` trigger and the job token needs `issues: write`
(or `pull-requests: write`) so Titra can remove the label:

```yaml
on:
  issues:
    types: [opened, labeled]
jobs:
  triage:
    if: github.event.action == 'opened' || github.event.label.name == 'titra:approve'
```

Set `approve-label: ""` to turn approvals off.

## Policy

The built-in defaults block the actions that turned real 2026 incidents into compromises: pushing code, approving or merging PRs, dispatching other workflows, publishing packages, and reading credential stores. Write your own with `titra init`:

```yaml
version: 1
mode: enforce
default: allow
allowed_domains:
  - api.mycorp.com
  - "*.internal"
rules:
  - id: block-git-push
    description: Agent must not push code
    action: block
    severity: critical
    match:
      tool: git
      args_regex: '(^|\s)push(\s|$)'
```

Rules are first-match-wins. `match.tool` is the command name; `match.args_regex` is tested against the joined arguments.

## Claude Code hook

To record and gate the agent's own tool calls, add Titra as a `PreToolUse` hook (Titra's Action sets this up for you when it detects Claude Code):

```json
{ "hooks": { "PreToolUse": [ { "matcher": "*",
  "hooks": [ { "type": "command", "command": "titra hook claude" } ] } ] } }
```

## CLI

```
titra install   # set up the shims and emit the guard environment
titra trace start|stop|collect   # whole-job kernel tracing (needs root)
titra hook claude                # Claude Code PreToolUse hook
titra report --format md|text|json [--state DIR] [--fail-on block|any|off]
titra init      # write a starter policy
```

## Try it

Copy [`examples/.github/workflows/demo-blocked.yml`](examples/.github/workflows/demo-blocked.yml) into a repo and run it from the Actions tab. A stand-in agent tries seven attacks; Titra blocks them, catches the two that dodge the shims, and fails the check. Locally:

```
make demo          # command-level blocking, no root
sudo make demo-trace   # full product: tracing + report (Linux)
```

## Titra for Organizations (paid)

The Action above is free and open source. For a security team running agents
across many repos, Titra for Organizations adds a GitHub App and a hosted
dashboard. Install the App on your org, add one org secret, and point the Action
at the dashboard:

```yaml
      - name: Titra
        uses: ChelateSec/titra@v1
        with:
          mode: enforce
          server: https://app.chelate.tech
          token: ${{ secrets.TITRA_TOKEN }}
```

What it adds:

- **Live dashboard, built for big orgs.** Repos → runs → one run. It opens on
  what *needs review* (blocked or flagged runs nobody has dealt with); the
  thousands of clean runs stay one click away. Each run shows who triggered it,
  whether they're trusted, what the agent's token could write, and what Titra
  stopped first, with the agent's own tool calls and the rest of the job folded
  below. **Mark reviewed** clears a run from the queue (approving a re-run does
  it automatically). Each person sees only the orgs they belong to on GitHub.
- **Verdicts on pull requests.** A `Titra` Check Run on the PR: failed if
  something was blocked, neutral if something was flagged, linked to the run.
- **Org-wide policy.** One policy for every guarded job. **Lock** it and repos
  can't swap in their own policy or downgrade the mode. A run that does anyway is
  flagged as *drift* on the dashboard and on its PR.
- **Coverage.** Scans every repo the App can see and lists the workflows that run
  an AI agent, which of those run without Titra, and which an outsider can
  trigger.

New installs get a 14-day trial of everything. After that, runs keep streaming
to the dashboard; PR checks, org policy and coverage need the Pro plan.

The token in `TITRA_TOKEN` is ingest-only: it can send reports for its own
org's repos and read the org policy. It can't read the dashboard or write into
another org. Titra for Organizations is a separate commercial product; it is not
part of this repository. Contact [Chelate Sec](https://www.chelate.tech/).

## How it fits with Shrike

[Shrike](https://github.com/ChelateSec/shrike) finds which of your workflows an outsider could hijack. Titra guards the ones you can't lock down. Shrike tells you where the risk is; Titra contains it.

## License

Apache-2.0.
