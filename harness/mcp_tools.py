"""Local MCP tool server (stdio) that records the size of every tool call at the tool boundary.

Benign tools only, all confined to one workspace folder: word_count, list_dir, read_file, write_file.

Every JSON-RPC message is one line of JSON on stdin or stdout (the MCP stdio transport). For each message the server
writes one JSON line to the tool log named by UT_TOOL_LOG:
  event=rpc        method, direction (in or out), exact line length in bytes without the newline
  event=tool_call  tool name, call id, args_bytes, msg_bytes, result_bytes, is_error, times

args_bytes is the UTF-8 length of the call's arguments object written as compact JSON
(json.dumps with separators (',', ':') and ensure_ascii=False). msg_bytes and result_bytes are the exact lengths of
the request line received and the response line sent. Argument and result contents are never logged.

Standard library only.
"""
from __future__ import annotations

import json
import os
import sys
import time

SERVER_INFO = {"name": "bench-tools", "version": "1.0.0"}
DEFAULT_PROTOCOL = "2025-06-18"
MAX_READ = 1 << 20

TOOLS = [
    {"name": "word_count", "description": "Count the words in a text.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "list_dir", "description": "List the entries of a folder inside the workspace.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "read_file", "description": "Read a UTF-8 text file inside the workspace (first 1 MB).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write a UTF-8 text file inside the workspace.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                     "required": ["path", "content"]}},
]


class ToolError(Exception):
    pass


def compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Server:
    def __init__(self, workspace: str, log_path: str | None):
        self.root = os.path.realpath(workspace)
        os.makedirs(self.root, exist_ok=True)
        self.log = open(log_path, "a", encoding="utf-8", buffering=1) if log_path else None

    def record(self, rec: dict) -> None:
        if self.log:
            self.log.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self.log.flush()

    def inside(self, path: str) -> str:
        full = os.path.realpath(os.path.join(self.root, path))
        if full != self.root and not full.startswith(self.root + os.sep):
            raise ToolError("path is outside the workspace")
        return full

    def run_tool(self, name: str, args: dict) -> str:
        if name == "word_count":
            return str(len(str(args.get("text", "")).split()))
        if name == "list_dir":
            full = self.inside(args.get("path", "."))
            return "\n".join(sorted(os.listdir(full)))
        if name == "read_file":
            with open(self.inside(args["path"]), "r", encoding="utf-8", errors="replace") as f:
                return f.read(MAX_READ)
        if name == "write_file":
            full = self.inside(args["path"])
            os.makedirs(os.path.dirname(full), exist_ok=True)
            data = str(args.get("content", ""))
            with open(full, "w", encoding="utf-8") as f:
                f.write(data)
            return f"wrote {len(data.encode('utf-8'))} bytes"
        raise ToolError(f"unknown tool: {name}")

    def answer(self, msg: dict):
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "initialize":
            asked = params.get("protocolVersion")
            version = asked if isinstance(asked, str) and len(asked) == 10 else DEFAULT_PROTOCOL
            return {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            try:
                text, is_error = self.run_tool(params.get("name"), params.get("arguments") or {}), False
            except (ToolError, OSError, KeyError) as e:
                text, is_error = f"error: {e}", True
            return {"content": [{"type": "text", "text": text}], "isError": is_error}
        raise LookupError(method)

    def send(self, obj) -> int:
        line = compact(obj)
        sys.stdout.buffer.write(line + b"\n")
        sys.stdout.buffer.flush()
        return len(line)

    def serve(self) -> None:
        for raw in sys.stdin.buffer:
            line = raw.rstrip(b"\r\n")
            if not line.strip():
                continue
            t_recv = time.time()
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            method = msg.get("method")
            self.record(dict(event="rpc", direction="in", method=method, bytes=len(line), t=t_recv))
            if "id" not in msg or method is None:
                continue  # notifications and responses to the server need no answer
            try:
                reply = {"jsonrpc": "2.0", "id": msg["id"], "result": self.answer(msg)}
            except LookupError:
                reply = {"jsonrpc": "2.0", "id": msg["id"],
                         "error": {"code": -32601, "message": f"method not found: {method}"}}
            out = self.send(reply)
            t_done = time.time()
            self.record(dict(event="rpc", direction="out", method=method, bytes=out, t=t_done))
            if method == "tools/call":
                params = msg.get("params") or {}
                self.record(dict(event="tool_call", tool=params.get("name"), id=msg["id"],
                                 args_bytes=len(compact(params.get("arguments") or {})), msg_bytes=len(line),
                                 result_bytes=out, is_error=reply.get("result", {}).get("isError", True),
                                 t_recv=t_recv, t_done=t_done))


def main():
    Server(os.environ.get("UT_WORKSPACE", os.getcwd()), os.environ.get("UT_TOOL_LOG")).serve()


if __name__ == "__main__":
    main()
