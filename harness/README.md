# Collection harness (benign runs)

Testbed that runs benign agent tasks and records, for every clean run, the exact byte length of each model call and
each tool call, next to a packet capture of that run. It runs on a Linux VM with root, because packet capture and
per-run network isolation need control of the operating system. Everything after collection runs in Colab.

| File | Role |
|---|---|
| `call_gateway.py` | Gateway the agent calls instead of the model endpoint. Logs the exact request and response body length of every call (JSON lines), forwards the request unchanged apart from Host and the upstream path prefix, streams the response back as it arrives, keeps one upstream connection per agent connection. Upstream TLS keys go to a key log for ground-truth labelling only. `--hold-until` is used only to prepare a warm home. |
| `homes.py` | Warm template homes, one per agent version, and their private copy into each run's home. |
| `mcp_tools.py` | Local MCP tool server (stdio) with benign workspace tools. Logs each tool call's argument size at the tool boundary. |
| `netns.py` | One network namespace per run, with NAT, public DNS, containment rules and a capture on the run's own interface. The veth pair takes the uplink's MTU and has segmentation and receive offloads off, and tcpdump writes every packet as it arrives, so the capture holds wire-size packets and no packet is lost when it stops. |
| `offline_check.py` | Checks that need no network or root: exact sizes from 0 B to 1 MB, unbuffered streaming, connection reuse, reconnects, TLS key log, MCP tool log, and (with `--agents`) Claude Code and Codex against a local fake endpoint. |
| `vm_gate.py` | Checks on the VM before any collection: isolation and capture, DeepSeek Anthropic and Responses APIs through the gateway, key-log decryption, both agents through the gateway, and the traffic of each agent straight to DeepSeek compared with its traffic through the gateway. |
| `pilot_tasks.py` | The ten benign tasks of the collection pilot and their synthetic workspace inputs. |
| `pilot.py` | The collection pilot: 60 benign runs through the harness, per-run labels, tool-call record, cost guard, manifests, resume and the pilot quality marks. |
| `vm_setup.sh` | Installs the system packages (including ethtool), Node.js 22 and the pinned agent versions on Ubuntu 24.04. |

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

Benign runs represent a returning user with a warm home, not a first launch. Each agent version has one template home,
made at the start of each gate or collection session by one trivial task run from an empty home and saved under
`data/harness/homes/<agent>-<version>/` with a `manifest.json`. Every run gets its own copy of the template before the
agent starts; templates are never shared between runs. All runs therefore carry the template's installation identity,
as one user's sessions would.

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

## Collection pilot

After the gate passes, the pilot collects a small set of benign runs through the harness to measure the call-level
benign floor that ANT could not give (ANT has no per-call sizes). `pilot_tasks.py` holds ten benign tasks across four
of ANT's scenarios (artifact processing 3, business services 2, general knowledge 2, scientific evidence 3);
`pilot.py` runs them with both agents, three times each, one run at a time: 10 tasks x 2 agents x 3 repeats = 60 runs.

Every task is self-contained inside the run's workspace: its inputs are synthetic strings written there before the
agent starts, and no task needs the public internet, a real credential or real personal data. Live web pages are not
used: uncontrolled third-party traffic would break the clean benign floor (model host plus the agent's own background
channel) and differ between the three repeats.

Each agent keeps its default tool set next to the four benign MCP tools. With the settings used here (tested with the
pinned versions), Claude Code in print mode runs its Read tool inside the workspace and read-only Bash commands, and
refuses Read outside the workspace, Write, Edit, WebFetch and WebSearch; Codex (workspace-write sandbox, approval never,
web search disabled) runs shell commands that can read outside the workspace and write inside it, with network blocked
inside its sandbox. The MCP tool log sees only MCP calls, so the pilot also records every tool call, built-in or MCP,
from the agent's own event output (Claude Code `--output-format stream-json`, Codex `exec --json`). Switching to that
output leaves every request byte for byte the same.

Each run keeps, under `data/harness/pilot/<time>/runs/<run_id>/` (git-ignored): the gateway call log, the MCP tool log,
`agent_tools.jsonl` (every tool call from the event output), the capture, `net.json`, the agent output, the workspace,
`labels.json` and `manifest.json`. `labels.json` is the per-call ground-truth table built straight after the run from
its TLS key log, the same decryption the gate's V4 does: each logged call is paired with the decrypted request sent on
the same upstream connection (in order within that connection) and its decrypted length is checked against the
gateway's logged length. The key log is deleted the moment `labels.json` is written and is never a detector input. The
run's home (a copy of the template, about 85 MB for Codex) is deleted after the run; the manifest names the template.

A run whose model call the endpoint drops is rerun once; both records are kept, the first flagged, and the rerun is the
run that counts. A run that stops on an error is set aside and recorded, and the pilot goes on. The cost guard reads
the DeepSeek balance before the warm-up runs and before every run (and rerun), and stops cleanly when the balance
cannot be read, is not available, or is at or below the floor (`--balance-floor`, in the first currency DeepSeek
lists); each run is capped at 300 s, Claude Code also at 12 turns. A stopped pilot is continued with `--resume <time>`,
which skips every run that already has a manifest. `pilot.json` is rewritten after every run.

Pilot quality marks, fixed before the run (kept runs: not a flagged first attempt, not a run that stopped on an error):
Q1 at least 95% of kept runs clean on the wire; Q2 every kept run's labels hold (every model-call request body sent to
the endpoint agrees, every decrypted request is paired, nothing on the model host's connections reads as HTTP without
the key log); Q3 no background download over 1,000,000 bytes from any host other than the model host in any pilot run,
flagged first attempts included; Q4 every kept run's manifest complete; Q5 at least 95% of kept runs completed (exit 0,
every model call answered 200, the agent's own result not an error). The pilot passes only when Q1 to Q5 pass and the
set is complete: every planned run kept, no early stop, a warm template for every agent. Codex's upload to
`ab.chatgpt.com` is reported against run time and model calls.

### Run the pilot on the VM

Run inside `tmux`, so a dropped SSH connection does not stop the pilot (on SIGHUP or SIGTERM the pilot still cleans
up and deletes its key logs):

    tmux new -s pilot
    export DEEPSEEK_API_KEY=...                 # kept in the environment only, never written to disk
    sudo -E python3 harness/pilot.py --only-task artifact_sales_summary --only-agent claude   # smoke test, 3 runs
    sudo -E python3 harness/pilot.py --upload gs://<bucket>/pilot                         # full pilot + upload
    sudo -E python3 harness/pilot.py --resume <time> --upload gs://<bucket>/pilot         # continue a stopped pilot

The upload is refused while any key log is left or any file contains the API key, and key logs are excluded from the
copy.

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

After the pilot, the notebook's Drive cell copies `gs://<bucket>/pilot/<time>` into
`data/harness/pilot/<time>` in the repository folder on Drive.

## Fixed rules

- Benign tasks only. No real credentials and no real user data in any run.
- The decrypted view of a capture exists only to label which bytes were real content, as a check on the byte-budget
  analysis. It is never an input to the detector.
- Key logs are deleted with the testbed and never released. Captures, key logs and call logs live under `data/` and
  are never committed. Run bundles move from the VM to Drive through a Google Cloud Storage bucket, with key logs
  already deleted; no credentials go in the repo.
