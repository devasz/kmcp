"""Dependency-free MCP stdio client used by the live E2E demo and benchmarks."""
import json, subprocess, time


class Mcp:
    def __init__(self, binary, *flags):
        self.p = subprocess.Popen([binary, *flags], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.n = 0
        self.lat = {}  # tool -> [seconds]
        self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo", "version": "0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, msg):
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()

    def _rpc(self, method, params):
        self.n += 1
        self._send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server closed: " + self.p.stderr.read())
            msg = json.loads(line)
            if msg.get("id") == self.n:
                return msg

    def tools(self):
        return [t["name"] for t in self._rpc("tools/list", {})["result"]["tools"]]

    def call(self, _tool, **args):
        """Returns (is_error, payload) where payload is parsed JSON when possible."""
        t0 = time.perf_counter()
        msg = self._rpc("tools/call", {"name": _tool, "arguments": args})
        self.lat.setdefault(_tool, []).append(time.perf_counter() - t0)
        if "error" in msg:
            return True, msg["error"]["message"]
        res = msg["result"]
        text = "".join(c.get("text", "") for c in res["content"])
        try:
            return bool(res.get("isError")), json.loads(text)
        except ValueError:
            return bool(res.get("isError")), text

    def ok(self, _tool, **args):
        err, out = self.call(_tool, **args)
        if err:
            raise RuntimeError(f"{_tool}({args}) failed: {out}")
        return out

    def close(self):
        self.p.stdin.close()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
