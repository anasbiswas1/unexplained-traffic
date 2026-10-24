# Collection harness (benign runs)

Testbed that runs benign agent tasks and records, for every clean run, the exact byte length of each model call and
each tool call, next to a packet capture of that run. It runs on a Linux VM with root, because packet capture and
per-run network isolation need control of the operating system. Everything after collection runs in Colab.

| File | Role |
|---|---|
| `call_gateway.py` | Gateway the agent calls instead of the model endpoint. Logs the exact request and response body length of every call (JSON lines), forwards the request unchanged apart from Host and the upstream path prefix, streams the response back as it arrives, keeps one upstream connection per agent connection. Upstream TLS keys go to a key log for ground-truth labelling only. `--hold-until` is used only to prepare a warm home. |
| `homes.py` | Warm template homes (one per agent version for the gate, one per agent version and model for the collection) and their private copy into each run's home. |
| `mcp_tools.py` | Local MCP tool server (stdio) with benign workspace tools and `fetch_url`, which fetches public documentation pages from a fixed allowlist of hosts and refuses every other URL. Logs each tool call's argument size at the tool boundary, and for `fetch_url` the host, path, exact HTTP request and response sizes, connection addresses and times. |
| `netns.py` | One network namespace per run, with NAT, public DNS, containment rules and a capture on the run's own interface. The veth pair takes the uplink's MTU and has segmentation and receive offloads off, and tcpdump writes every packet as it arrives, so the capture holds wire-size packets and no packet is lost when it stops. |
| `offline_check.py` | Checks that need no network or root: exact sizes from 0 B to 1 MB, unbuffered streaming, connection reuse, reconnects, TLS key log, MCP tool log, and (with `--agents`) Claude Code and Codex against a local fake endpoint. |
| `vm_gate.py` | Checks on the VM before any collection: isolation and capture, DeepSeek Anthropic and Responses APIs through the gateway, key-log decryption, both agents through the gateway, and the traffic of each agent straight to DeepSeek compared with its traffic through the gateway. |
| `pilot_tasks.py` | The twenty benign tasks of the collection (the pilot's ten unchanged, ten new, five of them needing `fetch_url`) and their synthetic workspace inputs. |
| `pilot.py` | The benign collection: 400 runs through the harness (20 tasks x 2 agents x 2 models x 5 repeats), per-run labels, tool-call record with network flags, fetch check against the capture, cost guard, manifests, resume and the collection marks. |
| `vm_setup.sh` | Installs the system packages (including ethtool, and bubblewrap and socat for Claude Code's command sandbox), Node.js 22 and the pinned agent versions on Ubuntu 24.04, lifts Ubuntu's AppArmor restriction on unprivileged user namespaces (kept across restarts in `/etc/sysctl.d/`) and lets others pass through the user's home (`o+x`), both needed by Claude Code's sandbox. |

## VM gate

    git clone https://github.com/anasbiswas1/unexplained-traffic.git
    cd unexplained-traffic
    sudo bash harness/vm_setup.sh
    export DEEPSEEK_API_KEY=...        # kept in the environment only, never written to disk
    sudo -E python3 harness/vm_gate.py

Output goes to `data/harness/vm_gate/<time>/` (git-ignored): captures, call logs, tool logs, agent output, a
`net.json` per run (uplink, MTU, offload states, capture counts) and `vm_gate.json`. Key logs are deleted when the gate
ends.

## Warm homes

Benign runs represent a returning user with a warm home, not a first launch. The gate keeps one template home per agent
version, saved under `data/harness/homes/<agent>-<version>/`; the collection keeps one per agent version and model,
saved under `data/harness/homes/<agent>-<version>-<model>/` and made by a warm-up run on that model, because Claude
Code keeps a cache entry per model in its home (`clientDataCacheSlots` in `.claude.json`, seen with the pinned version),
so a run on one model from a home warmed on another would start on a cache miss. Codex writes the model only to its
`config.toml`, which every run rewrites; it gets per-model templates too, so both agents follow one rule. Templates are
made at the start of each gate or collection session by one trivial task run from an empty home, each with a
`manifest.json`. Every run gets its own copy of the template before the agent starts; templates are never shared
between runs. All runs therefore carry the template's installation identity, as one user's sessions would.

- Codex syncs its plugin catalogue (`github.com/openai/plugins`) in the background at every launch and keeps the result
  only if the sync finishes before the agent exits. From an empty home a short run downloads about 25 MB and throws it
  away, so every such run downloads it again. The warm-up therefore holds its first model call at the gateway until
  the sync has finished (`.codex/.tmp/plugins.sha` exists), and the template is saved only then. A run from that home
  checks the remote commit (`git ls-remote`, about 40 KB) and fetches again only if the catalogue has changed upstream
  since the template was made.
- Claude Code showed no comparable first-launch download in testing (about 14 KB, as on a warm launch); its template
  is made the same way, without the hold.
- No template file may contain the API key.

V6, V7 and V8 report bytes up and down per remote host for every run and fail a run that downloads more than 1,000,000
bytes from any host other than the model host.

## Agent settings on DeepSeek

- Claude Code, from DeepSeek's Claude Code guide: `ANTHROPIC_BASE_URL` (the gateway, which forwards to
  `https://api.deepseek.com/anthropic`), `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_MODEL=deepseek-flash[1m]`,
  `ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-flash[1m]`, `ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-flash[1m]`,
  `ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-flash`. Local MCP tools reach the model as ordinary tool definitions.
- Codex, from DeepSeek's Codex guide: provider `base_url` (the gateway, which forwards to `https://api.deepseek.com`),
  `wire_api = "responses"`, model `deepseek-flash`; the key is read from `DEEPSEEK_API_KEY` through `env_key`.
- The collection also uses `deepseek-v4-pro`, the other model DeepSeek's model list names. For it, Claude Code gets the
  same four settings with `deepseek-v4-pro` in place of `deepseek-flash` (`vm_gate.claude_model_env`), so every call,
  whichever of its model settings Claude Code uses, goes to the run's model; Codex gets `model = "deepseek-v4-pro"`
  (`offline_check.codex_config`). Checked with the pinned versions against a local fake endpoint: every request of a
  run names the run's model (Claude Code removes the `[1m]` marker before sending).

## Benign collection

After the gate passed and the pilot (`20261024_031259`, notebook 03) showed that the call log explains every logged
call to the byte, the collection gathers the benign runs the analysis needs: `pilot_tasks.py` holds twenty benign tasks
across ANT's five scenarios (artifact processing, business services, general knowledge, scientific evidence and
security testing, four each); `pilot.py` runs them with both agents on both models, five times each, one run at a time:
20 tasks x 2 agents x 2 models x 5 repeats = 400 runs. The runs go in rounds (round r holds repeat r of every task,
model and agent), so a collection stopped part way is balanced. With five repeats, each held-out-task fold has 19 tasks
x 5 = 95 calibration runs per agent and model.

The first ten tasks are the pilot's, unchanged. Of the ten new ones, five need the MCP tool `fetch_url`: each names one
public documentation page in its prompt (RFC 4180, RFC 6585 and RFC 2119 on `www.rfc-editor.org`, and the Python 3.12
`statistics` and `secrets` pages on `docs.python.org`). These are the only pages any task asks for: RFCs never change,
and the Python 3.12 pages change only with a 3.12 security release, so the repeats of a task fetch the same page. All
other tasks are self-contained inside the run's workspace. The security-testing tasks are defensive reviews of
invented inputs (an SSH settings file against a written baseline, a login log, two short code files); none of them
probes, scans or attacks anything. No task uses a real credential or real personal data, and every input is invented.

### The network tool

`fetch_url` is the only tool with a network path. It fetches one page per call over HTTPS from the hosts in
`mcp_tools.FETCH_HOSTS` (`docs.python.org`, `www.rfc-editor.org`), on port 443, with no redirects followed; any other
host, scheme, port, user name or a path that is not printable ASCII is refused before any DNS lookup or connection. The
agent starts the tool server inside the run's namespace, so each fetch is a logged tool call whose connection is in the
run's capture. `tools.jsonl` logs, for every call, the host and path, whether and why it was refused, the exact HTTP
request and response bytes inside the TLS connection, the connection's local and server address (which tie the call to
its flow in the capture) and its times, and it writes a `fetch_open` line the moment a connection is open, so a fetch
cut off by the end of its run (an agent timeout) is still a logged connection. The read stops when the response is
complete (its declared length or the last chunk), when the server closes, or at 1,000,000 bytes. The agent gets the
page as text, at most 40,000 characters. `agent_tools.jsonl` marks each tool call with `network`: true only for a
`fetch_url` call that opened a connection.

Each agent keeps its default tool set next to the five MCP tools, and both get the same terms as closely as the pinned
versions allow: write access in the workspace, a shell that runs any command, no network from their own tools, and no
writes outside the workspace other than temporary files (see the differences below).

- Codex: workspace-write sandbox, approval never, web search disabled (as in the gate).
- Claude Code: permission mode `acceptEdits` (its Write and Edit tools write inside the workspace without asking),
  Bash allowed, with every Bash command inside Claude Code's own sandbox, set in the run's `claude_settings.json`:
  `sandbox.enabled`, `autoAllowBashIfSandboxed`, `allowUnsandboxedCommands: false` (a command cannot ask to run
  outside the sandbox), `failIfUnavailable: true` (Claude Code refuses to start when the sandbox cannot run) and no
  allowed network domain; and `--disallowedTools WebFetch,WebSearch`. The sandbox needs bubblewrap and socat
  (`vm_setup.sh` installs both), user namespaces without Ubuntu's AppArmor restriction and a home folder it can pass
  through (`vm_setup.sh` sets both). Before its first run the collection starts a bubblewrap sandbox with its own user
  namespace and without network inside the collection folder, and stops if it cannot. That check fails on a home
  folder others cannot pass through (tested; the pilot's check, without a user namespace and without entering the
  folder, passed there while Claude Code's sandboxed Bash failed). Whether it also fails on the AppArmor restriction
  as Claude Code meets it was not tested (no AppArmor on the test machine); the smoke test runs Claude Code's sandbox
  for real.

WebFetch is disallowed because the pilot's settings did not stop it everywhere: under them Claude Code 2.1.302 asked
before WebFetch reached `example.com` or `www.rfc-editor.org`, and was refused, but fetched from `docs.python.org`
without asking. With `docs.python.org` on the fetch allowlist, that would be a second network path, outside the tool
log. With the flag, neither WebFetch nor WebSearch is offered to the model, and a call to WebFetch is refused
as "No such tool available". No pilot task asked for the web, so the pilot's runs are not affected.

Tested with the pinned versions (Claude Code 2.1.302, Codex 0.163.0), from a workspace outside `/tmp` as on the VM:

| | Claude Code | Codex |
|---|---|---|
| write a file in the workspace (file tool or shell) | runs | runs (shell) |
| shell commands of any form (pipes, loops, variables, here-documents, Python) | run | run |
| write outside the workspace from the shell (parent folder, `/root`) | read-only file system | read-only file system |
| write outside the workspace with a file tool | refused | (no file tool) |
| network from the shell | blocked | blocked |
| read outside the workspace from the shell | runs | runs |
| read outside the workspace with the Read tool | refused | (no Read tool) |
| fetch or search the web with a built-in tool | not offered (WebFetch, WebSearch disallowed) | disabled |
| `fetch_url` to an allowlisted host | runs, connection from the tool server | runs, connection from the tool server |
| `fetch_url` to any other host | refused by the tool, no connection | refused by the tool, no connection |

The differences that remain:

- Temporary files: Codex's shell may also write anywhere in `/tmp`; Claude Code's sandboxed shell may write only to
  its own temporary folder, which it sets as the shell's `TMPDIR` (`/tmp/claude-0` when it runs as root). The run's
  home is read-only to it.
- Request size: the sandbox adds its rules to the description of Claude Code's Bash tool, so each Claude Code model
  request is about 6.8 KB larger than with the gate's settings (measured in the pilot); disallowing WebFetch and
  WebSearch removes their two tool definitions, and the fifth MCP tool adds one. The gate's gateway-versus-direct
  comparison (V8) used the gate's settings.
- Refusals: what Claude Code still refuses (its file tools outside the workspace) appears as a `permission_denied`
  entry in `agent_tools.jsonl` and the manifest. Codex asks for nothing (approval never); a command its sandbox stops
  simply fails, and shows as a failed shell call. A `fetch_url` call to a host off the allowlist is a tool call that
  returns an error, for both agents.

The MCP tool log sees only MCP calls, so the collection also records every tool call, built-in or MCP, and every
permission refusal from the agent's own event output (Claude Code `--output-format stream-json`, Codex `exec --json`).
Switching to that output leaves every request byte for byte the same. The readers take a nested field only when it has
the expected type (a refusal event's `message` is a string, for example), so an event of an unexpected shape is
skipped, not fatal.

Each run keeps, under `data/harness/pilot/<time>/runs/<task>__<agent>__<model>__r<repeat>/` (git-ignored): the gateway
call log, the MCP tool log, `agent_tools.jsonl` (every tool call with its network flag, and every permission refusal,
from the event output), the capture, `net.json`, the agent output, the workspace, `labels.json`, `manifest.json` and,
for Claude Code, `claude_settings.json`. `labels.json` is the per-call ground-truth table built straight after the run
from its TLS key log, the same decryption the gate's V4 does: each logged call is paired with the decrypted request sent
on the same upstream connection (in order within that connection) and its decrypted length is checked against the
gateway's logged length. The key log is deleted the moment `labels.json` is written and is never a detector input.
The run's home (a copy of the template, about 85 MB for Codex) is deleted after the run; the manifest names the
template. The manifest and the `pilot.json` row carry the run's model.

A run whose model call the endpoint drops is rerun once; both records are kept, the first flagged, and the rerun is the
run that counts. A run that stops on an error is set aside and recorded, and the collection goes on; its folder keeps
the capture, the call log, the agent output and `labels.json` (when the agent had finished), without the key log or the
home copy, and its row in `pilot.json` takes the set-aside folder's name, so every row names its own folder and the
rerun on resume keeps the planned name. The cost guard reads the DeepSeek balance before the warm-up runs and before
every run (and rerun), and stops cleanly when the balance cannot be read, is not available, or is at or below the
floor (`--balance-floor`, in the first currency DeepSeek lists); each run is capped at 300 s, Claude Code also at 12
turns. A stopped collection is continued
with `--resume <time>`, which keeps the collection's own plan, skips every run that already has a manifest and makes
warm templates only for the agents and models that still have runs. The VM may be stopped and started between
sessions. `pilot.json` is written before the warm-ups (so a session stopped during them keeps its plan) and rewritten
after every run.

Collection marks, fixed before the run (kept runs: not a flagged first attempt, not a run that stopped on an error):
Q1r at least 95% of kept runs have no testbed fault on the wire (every wire failure reason except upload bytes resent,
the rule of notebook 03; runs with resent upload are reported); Q2 every kept run's labels hold (every model-call
request body sent to the endpoint agrees, every decrypted request is paired, nothing on the model host's connections
reads as HTTP without the key log); Q4 every kept run's manifest complete; Q5 at least 95% of kept runs completed (exit
0, every model call answered 200, the agent's own result not an error); Q6 in every kept run, every `fetch_url` call
that opened a connection has its flow in the capture (same local port and server address, first packet within the
call's time, TLS server name equal to the requested host), no `fetch_url` call reached a host outside the allowlist (by
the tool log or by the capture's server name), and every connection in the capture to an allowlisted host is a logged
`fetch_url` call. The collection passes only when Q1r, Q2, Q4, Q5 and Q6 pass and the set is complete: every planned run
(agent x model x task x repeat) kept exactly once, no early stop, a warm template for every agent and model that still
had runs. Reported, not marked: the largest background download and upload per host for each agent and model (all
runs, flagged first attempts included; background is every host other than the model host and the fetch hosts; this was
the pilot's Q3), the runs whose background download is over 1,000,000 bytes, the `fetch_url` calls per agent, model and
host, and Codex's upload to `ab.chatgpt.com` against run time and model calls.

### Run the collection on the VM

Run inside `tmux`, so a dropped SSH connection does not stop the collection (on SIGHUP or SIGTERM it still cleans up
and deletes its key logs). Pull the repository and rerun `vm_setup.sh` first: it now lifts the user-namespace
restriction (kept across restarts) and opens the home folder for the sandbox.

    tmux new -s collect
    cd ~/unexplained-traffic && git pull
    sudo bash harness/vm_setup.sh
    export DEEPSEEK_API_KEY=...                 # kept in the environment only, never written to disk
    # smoke test: one network task on the new model, both agents, 5 repeats = 10 runs
    sudo -E python3 harness/pilot.py --only-task general_rfc_keywords --only-model deepseek-v4-pro
    # full collection, 400 runs, uploaded at the end
    sudo -E python3 harness/pilot.py --upload gs://<bucket>/pilot
    # continue a stopped collection (also after the VM was stopped and started)
    sudo -E python3 harness/pilot.py --resume <time> --upload gs://<bucket>/pilot

`<time>` is the collection's folder name under `data/harness/pilot/`, printed on the first line of the run. After a VM
restart, `tmux` and `DEEPSEEK_API_KEY` must be set again; the user-namespace setting comes back by itself. The upload is
refused while any key log is left or any file contains the API key, and key logs are excluded from the copy.

### Bundles to Drive through a Google Cloud Storage bucket

The analysis runs in Colab, so the run bundles must reach the repository's git-ignored `data/` folder on Drive
(`unexplained-traffic/data/harness/pilot/<time>/`, next to `data/ant/`). The VM uploads to a bucket in the same
project, then a Colab cell copies the bundles into Drive. No credentials are written to the repo; the VM uses its own
service-account identity and Colab uses the signed-in Google account. One-time setup, run in Cloud Shell or on the VM
(set `VM` to the VM's name and `BUCKET` to a new, globally unique bucket name):

    VM=ut-harness
    BUCKET=<bucket>
    PROJECT=$(gcloud config get-value project)
    ZONE=$(gcloud compute instances list --filter="name=$VM" --format="value(zone.basename())")
    REGION=${ZONE%-*}
    SA=$(gcloud compute instances describe $VM --zone $ZONE --format="value(serviceAccounts[0].email)")
    echo '{"rule": [{"action": {"type": "Delete"}, "condition": {"age": 30}}]}' > lifecycle.json
    gcloud storage buckets create gs://$BUCKET --project $PROJECT --location $REGION \
        --uniform-bucket-level-access --lifecycle-file lifecycle.json
    gcloud storage buckets add-iam-policy-binding gs://$BUCKET --member "serviceAccount:$SA" \
        --role roles/storage.objectAdmin

The lifecycle rule deletes objects 30 days after upload; the Drive copy is the one that stays. Then check on the VM
that it can write to the bucket:

    gsutil ls gs://<bucket>
    echo ok | gsutil cp - gs://<bucket>/_writetest && gsutil rm gs://<bucket>/_writetest

If this fails with an access-scope error, the VM was created without a storage write scope. Add it, keeping the
default scopes (the VM must be stopped; `--scopes` replaces the VM's scope list):

    gcloud compute instances stop $VM --zone $ZONE
    gcloud compute instances set-service-account $VM --zone $ZONE --scopes default,storage-rw
    gcloud compute instances start $VM --zone $ZONE

After the collection, the analysis notebook's Drive cell copies `gs://<bucket>/pilot/<time>` into
`data/harness/pilot/<time>` in the repository folder on Drive.

## Fixed rules

- Benign tasks only. No real credentials and no real user data in any run. The only network a tool reaches is the
  fixed allowlist of public documentation hosts in `fetch_url`.
- The decrypted view of a capture exists only to label which bytes were real content, as a check on the byte-budget
  analysis. It is never an input to the detector.
- Key logs are deleted with the testbed and never released. Captures, key logs and call logs live under `data/` and
  are never committed. Run bundles move from the VM to Drive through a Google Cloud Storage bucket, with key logs
  already deleted; no credentials go in the repo.
