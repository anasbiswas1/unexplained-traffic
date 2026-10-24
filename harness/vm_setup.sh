#!/usr/bin/env bash
# Installs what the testbed needs on a fresh Ubuntu 24.04 VM (x86_64 or arm64). Run once as root from the repository
# root: sudo bash harness/vm_setup.sh
# The agent versions are pinned to the versions the offline checks were run with.
set -euo pipefail

NODE_VERSION=22.22.0
CLAUDE_CODE_VERSION=2.1.302
CODEX_VERSION=0.163.0

if [ "$(id -u)" -ne 0 ]; then echo "run as root"; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
# bubblewrap and socat: Claude Code's command sandbox needs both
apt-get install -y -q python3 iproute2 iptables tcpdump tshark openssl curl ca-certificates xz-utils git bubblewrap \
  socat ethtool

case "$(uname -m)" in
  x86_64) arch=x64 ;;
  aarch64) arch=arm64 ;;
  *) echo "unsupported machine $(uname -m)"; exit 1 ;;
esac

# Node.js from the official release, checked against the published SHA-256 list (the Ubuntu package is too old for
# the Claude Code npm package, which requires Node.js 22)
if [ "$(node --version 2>/dev/null || true)" != "v${NODE_VERSION}" ]; then
  tmp="$(mktemp -d)"
  file="node-v${NODE_VERSION}-linux-${arch}.tar.xz"
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/${file}" -o "${tmp}/${file}"
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" -o "${tmp}/SHASUMS256.txt"
  (cd "${tmp}" && grep " ${file}\$" SHASUMS256.txt | sha256sum -c -)
  tar -xJf "${tmp}/${file}" -C /usr/local --strip-components=1
  rm -rf "${tmp}"
fi

npm install -g --no-audit --no-fund "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" "@openai/codex@${CODEX_VERSION}"

echo "python3  $(python3 --version)"
echo "node     $(node --version)"
echo "claude   $(claude --version)"
echo "codex    $(codex --version)"
echo "tcpdump  $(tcpdump --version 2>&1 | head -1)"
echo "tshark   $(tshark --version 2>/dev/null | head -1)"
echo "ethtool  $(ethtool --version)"
echo "bwrap    $(bwrap --version)"
echo "socat    $(socat -V 2>/dev/null | grep -m1 'socat version')"
