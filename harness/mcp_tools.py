"""Local MCP tool server (stdio) that records the size of every tool call at the tool boundary.

Benign tools only. Four are confined to one workspace folder: word_count, list_dir, read_file, write_file. The fifth,
fetch_url, reads one public documentation page over HTTPS from a fixed allowlist of hosts (FETCH_HOSTS) and refuses
every other URL before any network use. The agent starts this server inside the run's network namespace, so every
fetch is a logged tool call whose connection is in the run's capture.

Every JSON-RPC message is one line of JSON on stdin or stdout (the MCP stdio transport). For each message the server
writes one JSON line to the tool log named by UT_TOOL_LOG:
  event=rpc        method, direction (in or out), exact line length in bytes without the newline (out: sent false
                   when the agent had gone and the reply could not be written)
  event=tool_call  tool name, call id, args_bytes, msg_bytes, result_bytes, is_error, sent, times, and for fetch_url a
                   fetch object (below)
  event=fetch_open host, path, local and remote address and times of a fetch_url connection, written the moment it
                   is open, so a fetch cut off by the end of its run (an agent timeout) is still in the log

args_bytes is the UTF-8 length of the call's arguments object written as compact JSON
(json.dumps with separators (',', ':') and ensure_ascii=False). msg_bytes and result_bytes are the exact lengths of
the request line received and the response line sent. Argument and result contents are never logged, with one
exception: the host and path of a fetch_url request, which the capture check needs.

fetch_url, one connection per call, no redirects followed, no proxy:
  - The URL must be https, on port 443, with no user name or password, and its host must be one of FETCH_HOSTS
    exactly (lower case, no trailing dot). The path and query must be printable ASCII. Anything else is refused with
    no DNS lookup and no connection.
  - The host is looked up (IPv4) and the first address is used; one TCP connection, TLS with the host as server name
    and the system's certificate store, one HTTP/1.1 GET with Connection: close and Accept-Encoding: identity, read
    until the response is complete (its declared length, or the last chunk of a chunked body), the server closes, or
    FETCH_MAX_BYTES have been read.
  - The fetch object in the log: host, path (allowed calls only), refused (the reason, or null), error (a network or
    protocol error, or null), status, request_bytes (the exact HTTP request written into the TLS connection),
    response_bytes (the exact HTTP response bytes read from it, head and body as sent), body_bytes (the body after
    removing chunked framing), cut (reading stopped at FETCH_MAX_BYTES), text_chars (characters of page text before
    the cut at FETCH_TEXT_MAX), local and remote (ip:port of the connection, which tie the call to its flow in the
    capture), tls (protocol version), and the times t_start (call received), t_connect (TCP connected) and t_done.
  - The agent gets the status line and the page text (HTML reduced to text), at most FETCH_TEXT_MAX characters.

Standard library only.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit

SERVER_INFO = {"name": "bench-tools", "version": "1.1.0"}
DEFAULT_PROTOCOL = "2025-06-18"
MAX_READ = 1 << 20

FETCH_HOSTS = ("docs.python.org", "www.rfc-editor.org")
FETCH_PORT = 443
FETCH_TIMEOUT = 30
FETCH_MAX_BYTES = 1_000_000
FETCH_TEXT_MAX = 40_000
USER_AGENT = "bench-tools/1.1"

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
    {"name": "fetch_url",
     "description": ("Fetch one public documentation page over HTTPS and return its text (at most "
                     f"{FETCH_TEXT_MAX:,} characters). Only these hosts are allowed: {', '.join(FETCH_HOSTS)}. "
                     "Redirects are not followed."),
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
]


class ToolError(Exception):
    pass


def compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------- fetch_url
def url_host(url) -> str:
    """The lower-case host of a URL, or '' when it has none or cannot be read."""
    try:
        return (urlsplit(str(url).strip()).hostname or "").lower()
    except ValueError:
        return ""


def check_url(url) -> tuple[str, str, str | None]:
    """(host, path, refusal): refusal is None when fetch_url may fetch the URL, otherwise the reason it is refused."""
    if not isinstance(url, str) or not url.strip():
        return "", "", "the url argument is missing or not a string"
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as e:
        return url_host(url), "", f"the URL cannot be read: {e}"
    host = (parts.hostname or "").lower()
    if parts.scheme.lower() != "https":
        return host, "", "only https URLs are allowed"
    if parts.username is not None or parts.password is not None:
        return host, "", "a URL with a user name or password is not allowed"
    if port not in (None, FETCH_PORT):
        return host, "", f"only port {FETCH_PORT} is allowed"
    if host not in FETCH_HOSTS:
        return host, "", f"host {host[:255] or '(none)'} is not on the allowlist ({', '.join(FETCH_HOSTS)})"
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if any(not (0x21 <= ord(c) <= 0x7E) for c in path):
        return host, "", "the URL path holds characters that are not printable ASCII"
    return host, path, None


def request_bytes(host: str, path: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: text/html, text/plain\r\n"
            f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")


def default_connect(host: str, port: int, timeout: float) -> socket.socket:
    """One TCP connection to the first IPv4 address of host (the run's namespace is IPv4 only)."""
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"no IPv4 address for {host}")
    return socket.create_connection(infos[0][4][:2], timeout=timeout)


def parse_head(head: bytes) -> tuple[int | None, dict]:
    """(status, headers with lower-case names) of an HTTP/1.1 response head, without its blank line."""
    lines = head.decode("iso-8859-1").split("\r\n")
    status = None
    words = lines[0].split(" ", 2)
    if len(words) >= 2 and words[0].startswith("HTTP/") and words[1].isascii() and words[1].isdigit():
        status = int(words[1])
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if colon:
            headers[name.strip().lower()] = value.strip()
    return status, headers


def declared_length(headers: dict) -> int | None:
    value = headers.get("content-length", "")
    return int(value) if value.isascii() and value.isdigit() else None


def is_chunked(headers: dict) -> bool:
    return "chunked" in headers.get("transfer-encoding", "").lower()


def dechunk(rest: bytes) -> tuple[bytes, bool]:
    """(body, complete) of a chunked body: the chunks' data, and whether the last chunk and the end of the trailers
    have arrived."""
    body, pos = bytearray(), 0
    while True:
        end = rest.find(b"\r\n", pos)
        if end < 0:
            return bytes(body), False
        size_text = rest[pos:end].split(b";")[0].strip()
        try:
            size = int(size_text, 16) if size_text and size_text.isascii() else None
        except ValueError:
            size = None
        if size is None:
            return bytes(body), False
        if size == 0:
            done = rest[end + 2:end + 4] == b"\r\n" or rest.find(b"\r\n\r\n", end) >= 0
            return bytes(body), done
        if end + 2 + size + 2 > len(rest):
            body += rest[end + 2:end + 2 + size]
            return bytes(body), False
        body += rest[end + 2:end + 2 + size]
        pos = end + 2 + size + 2


def response_complete(raw: bytes) -> bool:
    """The whole response has arrived: a status without a body (1xx, 204, 304), a declared length that the body has
    reached, or a chunked body whose last chunk has arrived. Lets the read stop without waiting for a server that keeps
    the connection open."""
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep:
        return False
    status, headers = parse_head(head)
    if status is not None and (status < 200 or status in (204, 304)):
        return True
    if is_chunked(headers):
        return dechunk(rest)[1]
    length = declared_length(headers)
    return length is not None and len(rest) >= length


def split_response(raw: bytes) -> tuple[int | None, dict, bytes]:
    """(status, headers in lower case, body bytes after removing chunked framing) of an HTTP/1.1 response."""
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep:
        return None, {}, b""
    status, headers = parse_head(head)
    if is_chunked(headers):
        return status, headers, dechunk(rest)[0]
    length = declared_length(headers)
    return status, headers, rest[:length] if length is not None else rest


class TextOf(HTMLParser):
    """The text of an HTML page: script, style and similar elements dropped, a line break at each block element,
    runs of spaces collapsed, empty lines dropped."""
    SKIP = {"script", "style", "noscript", "template", "svg"}
    BLOCK = {"p", "div", "br", "li", "ul", "ol", "dl", "dt", "dd", "tr", "table", "pre", "section", "article", "h1",
             "h2", "h3", "h4", "h5", "h6", "title", "blockquote", "header", "footer", "nav", "hr", "td", "th"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)

    def text(self) -> str:
        lines = (" ".join(line.split()) for line in "".join(self.parts).split("\n"))
        return "\n".join(line for line in lines if line)


def page_text(headers: dict, body: bytes) -> str:
    ctype = headers.get("content-type", "").lower()
    charset = "utf-8"
    for part in ctype.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key == "charset" and value:
            charset = value.strip('"')
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    if "html" in ctype or text.lstrip()[:15].lower().startswith(("<!doctype html", "<html")):
        parser = TextOf()
        parser.feed(text)
        parser.close()
        return parser.text()
    return text


class Server:
    def __init__(self, workspace: str, log_path: str | None, connect=default_connect, tls_context=None):
        """connect and tls_context are replaced only by the offline checks, which serve the allowlisted names from a
        local test server; the tool server itself always runs with the defaults."""
        self.root = os.path.realpath(workspace)
        os.makedirs(self.root, exist_ok=True)
        self.log = open(log_path, "a", encoding="utf-8", buffering=1) if log_path else None
        self.connect = connect
        self.tls_context = tls_context
        self.last_fetch = None

    def record(self, rec: dict) -> None:
        if self.log:
            self.log.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self.log.flush()

    def inside(self, path: str) -> str:
        full = os.path.realpath(os.path.join(self.root, path))
        if full != self.root and not full.startswith(self.root + os.sep):
            raise ToolError("path is outside the workspace")
        return full

    @staticmethod
    def fetch_object(host: str, refused: str | None, t_start: float) -> dict:
        return dict(host=host[:255], path=None, refused=refused, error=None, status=None, request_bytes=0,
                    response_bytes=0, body_bytes=0, cut=False, text_chars=0, local=None, remote=None, tls=None,
                    t_start=t_start, t_connect=None, t_done=None)

    def fetch(self, url) -> tuple[str, bool]:
        """(text for the agent, is_error). Sets self.last_fetch to the fetch object of the tool log."""
        t_start = time.time()
        host, path, refused = check_url(url)
        f = self.fetch_object(host, refused, t_start)
        self.last_fetch = f
        if refused:
            f["t_done"] = time.time()
            return f"error: {refused}", True
        f["path"] = path
        req = request_bytes(host, path)
        raw = bytearray()
        sock = None
        try:
            sock = self.connect(host, FETCH_PORT, FETCH_TIMEOUT)
            f["t_connect"] = time.time()
            local, remote = sock.getsockname(), sock.getpeername()
            f["local"], f["remote"] = f"{local[0]}:{local[1]}", f"{remote[0]}:{remote[1]}"
            self.record(dict(event="fetch_open", host=host, path=path, local=f["local"], remote=f["remote"],
                             t_start=t_start, t_connect=f["t_connect"]))
            ctx = self.tls_context or ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            f["tls"] = sock.version()
            sock.sendall(req)
            f["request_bytes"] = len(req)
            while len(raw) < FETCH_MAX_BYTES:
                chunk = sock.recv(min(65536, FETCH_MAX_BYTES - len(raw)))
                if not chunk:
                    break
                raw += chunk
                if response_complete(bytes(raw)):
                    break
            f["cut"] = len(raw) >= FETCH_MAX_BYTES
        except (OSError, ssl.SSLError, ValueError) as e:
            f["error"] = f"{type(e).__name__}: {e}"[:300]
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            f["response_bytes"] = len(raw)
            f["t_done"] = time.time()
        if f["error"] and not raw:
            return f"error: {f['error']}", True
        try:
            status, headers, body = split_response(bytes(raw))
        except Exception as e:
            f["error"] = f"response could not be read: {type(e).__name__}: {e}"[:300]
            return f"error: {f['error']}", True
        f["status"], f["body_bytes"] = status, len(body)
        if status is None:
            f["error"] = f["error"] or "no HTTP response head"
            return f"error: {f['error']}", True
        if headers.get("content-encoding", "identity").lower() not in ("", "identity"):
            f["error"] = f"the server sent a {headers['content-encoding']} body"
            return f"error: {f['error']}", True
        if 300 <= status < 400:
            return (f"HTTP {status}: the page moved to {headers.get('location', '(no location given)')}. "
                    "fetch_url does not follow redirects."), False
        try:
            text = page_text(headers, body)
        except Exception as e:
            f["error"] = f"page text could not be read: {type(e).__name__}: {e}"[:300]
            return f"error: {f['error']}", True
        f["text_chars"] = len(text)
        out = f"HTTP {status}\n{text[:FETCH_TEXT_MAX]}"
        if len(text) > FETCH_TEXT_MAX:
            out += f"\n[text cut at {FETCH_TEXT_MAX:,} of {len(text):,} characters]"
        if f["cut"]:
            out += f"\n[reading stopped at {FETCH_MAX_BYTES:,} bytes]"
        return out, status >= 400 or bool(f["error"])

    def run_tool(self, name: str, args: dict) -> tuple[str, bool]:
        """(text, is_error) of one tool call."""
        if name == "word_count":
            return str(len(str(args.get("text", "")).split())), False
        if name == "list_dir":
            full = self.inside(args.get("path", "."))
            return "\n".join(sorted(os.listdir(full))), False
        if name == "read_file":
            with open(self.inside(args["path"]), "r", encoding="utf-8", errors="replace") as f:
                return f.read(MAX_READ), False
        if name == "write_file":
            full = self.inside(args["path"])
            os.makedirs(os.path.dirname(full), exist_ok=True)
            data = str(args.get("content", ""))
            with open(full, "w", encoding="utf-8") as f:
                f.write(data)
            return f"wrote {len(data.encode('utf-8'))} bytes", False
        if name == "fetch_url":
            return self.fetch(args.get("url"))
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
            args = params.get("arguments") or {}
            try:
                if not isinstance(args, dict):
                    if params.get("name") == "fetch_url":
                        self.last_fetch = dict(self.fetch_object("", "arguments must be an object", time.time()),
                                               t_done=time.time())
                    raise ToolError("arguments must be an object")
                text, is_error = self.run_tool(params.get("name"), args)
            except (ToolError, OSError, KeyError) as e:
                text, is_error = f"error: {e}", True
            return {"content": [{"type": "text", "text": text}], "isError": is_error}
        raise LookupError(method)

    def send(self, obj) -> int:
        line = compact(obj)
        sys.stdout.buffer.write(line + b"\n")
        sys.stdout.buffer.flush()
        return len(line)

    def handle(self, line: bytes, send=None) -> None:
        """Answers one request line (without its newline) and logs it; send writes the reply and returns its length
        (the stdio writer by default)."""
        send = send or self.send
        if not line.strip():
            return
        t_recv = time.time()
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            return
        if not isinstance(msg, dict):
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})
            return
        method = msg.get("method")
        self.record(dict(event="rpc", direction="in", method=method, bytes=len(line), t=t_recv))
        if "id" not in msg or method is None:
            return  # notifications and responses to the server need no answer
        self.last_fetch = None
        try:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": self.answer(msg)}
        except LookupError:
            reply = {"jsonrpc": "2.0", "id": msg["id"],
                     "error": {"code": -32601, "message": f"method not found: {method}"}}
        try:
            out = send(reply)
            sent = True
        except OSError:          # the agent has gone (stopped or timed out): the call is still logged
            out, sent = len(compact(reply)), False
        t_done = time.time()
        self.record(dict(event="rpc", direction="out", method=method, bytes=out, t=t_done, sent=sent))
        if method == "tools/call":
            params = msg.get("params") or {}
            args = params.get("arguments") or {}
            rec = dict(event="tool_call", tool=params.get("name"), id=msg["id"], args_bytes=len(compact(args)),
                       msg_bytes=len(line), result_bytes=out, is_error=reply.get("result", {}).get("isError", True),
                       sent=sent, t_recv=t_recv, t_done=t_done)
            if params.get("name") == "fetch_url":
                rec["fetch"] = self.last_fetch
            self.record(rec)

    def serve(self) -> None:
        for raw in sys.stdin.buffer:
            self.handle(raw.rstrip(b"\r\n"))


def main():
    Server(os.environ.get("UT_WORKSPACE", os.getcwd()), os.environ.get("UT_TOOL_LOG")).serve()


if __name__ == "__main__":
    main()
