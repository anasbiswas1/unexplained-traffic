# Collection harness (benign runs)

Testbed that runs benign agent tasks and records, for every clean run, the exact byte length of each model call and
each tool call, next to a packet capture of that run. It runs on a Linux VM with root, because packet capture and
per-run network isolation need control of the operating system. Everything after collection runs in Colab.

| File | Role |
|---|---|
| `call_gateway.py` | Gateway the agent calls instead of the model endpoint. Logs the exact request and response body length of every call (JSON lines), forwards the request unchanged apart from Host and the upstream path prefix, streams the response back as it arrives, keeps one upstream connection per agent connection. Upstream TLS keys go to a key log for ground-truth labelling only. |
| `mcp_tools.py` | Local MCP tool server (stdio) with benign workspace tools. Logs each tool call's argument size at the tool boundary. |
| `netns.py` | One network namespace per run, with NAT, public DNS, containment rules and a capture on the run's own interface. The veth pair takes the uplink's MTU and has segmentation and receive offloads off, and tcpdump writes every packet as it arrives, so the capture holds wire-size packets and no packet is lost when it stops. |
| `offline_check.py` | Checks that need no network or root: exact sizes from 0 B to 1 MB, unbuffered streaming, connection reuse, reconnects, TLS key log, MCP tool log, and (with `--agents`) Claude Code and Codex against a local fake endpoint. |
| `vm_gate.py` | Checks on the VM before any collection: isolation and capture, DeepSeek Anthropic and Responses APIs through the gateway, key-log decryption, both agents through the gateway, and the traffic of each agent straight to DeepSeek compared with its traffic through the gateway. |
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

## Agent settings on DeepSeek

- Claude Code, from DeepSeek's Claude Code guide: `ANTHROPIC_BASE_URL` (the gateway, which forwards to
  `https://api.deepseek.com/anthropic`), `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_MODEL=deepseek-flash[1m]`,
  `ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-flash[1m]`, `ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-flash[1m]`,
  `ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-flash`. Local MCP tools reach the model as ordinary tool definitions.
- Codex, from DeepSeek's Codex guide: provider `base_url` (the gateway, which forwards to `https://api.deepseek.com`),
  `wire_api = "responses"`, model `deepseek-flash`; the key is read from `DEEPSEEK_API_KEY` through `env_key`.

## Fixed rules

- Benign tasks only. No real credentials and no real user data in any run.
- The decrypted view of a capture exists only to label which bytes were real content, as a check on the byte-budget
  analysis. It is never an input to the detector.
- Key logs are deleted with the testbed and never released. Captures, key logs and call logs live under `data/` and
  are never committed.
