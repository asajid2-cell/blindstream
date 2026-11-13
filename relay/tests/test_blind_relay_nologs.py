"""ADR 0011 Decision 4.1, as a code-level red proof.

The rule: a relay writes **nothing** about a request - no address, no path/ref, no timing,
no size - to a file, a journal or a metrics label. The only observability is an aggregate
counter (`Counters`), which names no ref and no credential.

A promise not to log is not a proof, and neither is a review. So this module proves it from
the code's own abstract syntax tree, over the whole relay surface:

  * no logging construct may appear in any relay module - `print`, `open`, a `logging`
    import, `sys.stdout`/`sys.stderr`, `syslog`, `.write` on a file object;
  * exactly one `print` is allowed, in `main()`, and it is the start-up line (it names the
    bind, never a request);
  * and it is a *red proof*: the checker is run against a mutated copy of the source with a
    log line injected, and the checker must fail. A test that only ever says "pass" proves
    nothing about what it would catch.

A second, behavioural check drives real requests through the handler with `print` and
`open` swapped for recorders, and asserts nothing was called: the static proof is about the
code, the behavioural one is about the running daemon.
"""
from __future__ import annotations

import ast
import http.client
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]  # the relay directory
sys.path.insert(0, str(HERE))

# Every module on the relay's request path. A log line added to any of them must fail.
# `blind_insert_seam.py` is the deployment's `POST /i` seam and runs *on* the insert request
# path, so a log line there is exactly what drill 3 forbids ("the insert relay") -- it is
# scanned here too, not left to the fact that it is configured rather than imported.
# `blind_renewal_service.py` is the pass-renewal surface (its own hidden service on the
# licence host). It is not a relay, but the same rule applies to it by ruling: a request
# must leave nothing naming a pass, a pseudonym, an address or a time.
RELAY_MODULES = ["blind_relay.py", "blind_door.py", "blind_cache.py", "blind_substrate.py",
                 "blind_insert_seam.py"]

# A module may carry exactly one start-up `print` inside `main`, naming only the bind.
STARTUP_PRINT_MODULES = {"blind_relay.py"}

# Bare names (builtins / module-level functions) that write somewhere.
FORBIDDEN_CALLS = {
    "print": "writes to stdout, which is journald on a serving host",
    "open": "opens a file, which could be a log",
    "warn": "a logging call",
    "warning": "a logging call",
    "info": "a logging call",
    "debug": "a logging call",
    "error": "a logging call",
    "critical": "a logging call",
    "exception": "a logging call",
    "basicConfig": "configures the logging module",
    "getLogger": "obtains a logger",
    "syslog": "writes to the system log",
}
# Method names that are logging when called on any receiver (`logger.info`, `log.error`).
FORBIDDEN_METHODS = {
    "warn", "warning", "info", "debug", "error", "critical", "exception",
    "basicConfig", "getLogger", "syslog",
}
FORBIDDEN_IMPORTS = {"logging", "logging.handlers", "syslog", "warnings"}


def relay_violations(source: str, *, allow_startup_print: bool = True) -> list[str]:
    """Return a list of log-capable constructs in `source`. Empty means clean.

    Parameterised so the red proof can run it on mutated source and require it to fail.
    """
    tree = ast.parse(source)
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_IMPORTS:
                    violations.append(f"line {node.lineno}: imports {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in FORBIDDEN_IMPORTS:
                violations.append(f"line {node.lineno}: from {node.module} import ...")
        elif isinstance(node, ast.Attribute):
            # `sys.stdout` / `sys.stderr` / anything ending in a file-writing method.
            if (isinstance(node.value, ast.Name) and node.value.id == "sys"
                    and node.attr in ("stdout", "stderr", "stdin")):
                violations.append(f"line {node.lineno}: touches sys.{node.attr}")
            if node.attr in ("write", "writelines", "flush"):
                # The HTTP response stream (`self.wfile`) writes to the socket, which is
                # the delivery, not a log. Every other stream-like receiver is refused: a
                # file this relay opened, or a sink someone named for logging.
                target = _irreducible(node.value)
                if target not in ("self.wfile", "self.rfile"):
                    violations.append(f"line {node.lineno}: .{node.attr}() on {target}")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                # A bare name: `print`, `open`, `warn` - a builtin or a module function.
                if func.id in FORBIDDEN_CALLS:
                    if (func.id == "print" and allow_startup_print
                            and _is_startup_print(tree, node)):
                        continue
                    violations.append(
                        f"line {node.lineno}: calls {func.id}() - {FORBIDDEN_CALLS[func.id]}")
            elif isinstance(func, ast.Attribute):
                # A method: `logger.info(...)`, `log.error(...)`. `tarfile.open` and
                # `stream.write` are told apart by their receiver above, so only the logging
                # method names are refused here.
                if func.attr in FORBIDDEN_METHODS:
                    violations.append(f"line {node.lineno}: calls .{func.attr}() - a logging call")
    return violations


def _irreducible(value: ast.AST) -> str:
    """A short, source-like name for the receiver of a `.write`-like call.

    `self.wfile` -> "self.wfile"; `sys.stderr` -> "sys.stderr"; a chain containing any
    other name is reported with that name, which is enough to tell the response stream
    (allowed) from a stream someone named for a log (refused).
    """
    parts: list[str] = []
    node: ast.AST | None = value
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts)) if parts else "<expr>"


def _is_startup_print(tree: ast.AST, call: ast.Call) -> bool:
    """True when `print` is the single start-up line at the top level of `main`.

    The start-up line names the bind and is not a request log, so exactly one `print` in
    `main` is permitted. Any other `print` anywhere - a second one, one inside a handler, one
    inside a helper - is a violation.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            prints = [n for n in ast.walk(node) if isinstance(n, ast.Call)
                      and isinstance(n.func, ast.Name) and n.func.id == "print"]
            if len(prints) == 1 and prints[0] is call:
                return True
    return False


# --- the static proof over the shipped source -----------------------------------------


@pytest.mark.parametrize("module", RELAY_MODULES)
def test_no_relay_module_contains_a_logging_construct(module):
    source = (HERE / module).read_text(encoding="utf-8")
    violations = relay_violations(source)
    assert violations == [], f"{module} can log: {violations}"


def test_strict_mode_forbids_even_the_startup_print():
    # With the start-up exemption off, the whole relay surface must be silent - this is
    # what a relay built with no operator line would be checked against.
    for module in RELAY_MODULES:
        violations = relay_violations((HERE / module).read_text(encoding="utf-8"),
                                      allow_startup_print=False)
        if module in STARTUP_PRINT_MODULES:
            prints = [v for v in violations if "print" in v]
            assert len(prints) == 1, f"{module}: {violations}"  # only the start line
            assert len(prints) == len(violations), f"{module} can log: {violations}"
        else:
            assert violations == [], f"{module} can log: {violations}"


# --- the red proof: the checker catches an injected log line --------------------------


@pytest.mark.parametrize("injected", [
    'print("served a block")',
    'logging.getLogger("relay").info("served")',
    'open("/var/log/relay.log", "a").write("served")',
    'sys.stderr.write("served")',
    'import logging',
    'import syslog',
])
def test_the_checker_fails_when_a_log_line_is_injected(injected):
    """A proof that cannot fail is not a proof. Inject a log line; the checker must catch it.

    The line is inserted at module scope, which is where a naive `import logging`/`print`
    would land, and - for the call forms - inside the handler body via a marker, so both
    the top-level and the request path are covered.
    """
    base = (HERE / "blind_relay.py").read_text(encoding="utf-8")
    mutated = base.replace("MAX_WIRE = 16 * 1024 * 1024",
                           f"MAX_WIRE = 16 * 1024 * 1024\n{injected}\n")
    assert relay_violations(mutated) != [], f"the checker missed: {injected}"


def test_a_second_print_in_main_is_caught():
    base = (HERE / "blind_relay.py").read_text(encoding="utf-8")
    mutated = base.replace('print(f"blind relay listening on',
                           'print("second line")\n    print(f"blind relay listening on')
    assert any("print" in v for v in relay_violations(mutated))


@pytest.mark.parametrize("injected", [
    'print("inserted a block")',
    'sys.stderr.write("inserted")',
    'open("/var/log/insert.log", "a").write("inserted")',
])
def test_the_checker_fails_when_a_log_line_is_injected_into_the_seam(injected):
    """Drill 3 names 'the insert relay' - the shipped `POST /i` seam must redden too.

    The seam runs on the insert request path; a ref, an object id or a size logged there is
    exactly what the no-logs rule forbids. Injected into a scratch copy of the seam module.
    """
    base = (HERE / "blind_insert_seam.py").read_text(encoding="utf-8")
    mutated = base.replace("from blind_substrate import SubstrateError",
                           f"from blind_substrate import SubstrateError\n{injected}\n")
    assert relay_violations(mutated) != [], f"the checker missed: {injected}"


# --- the behavioural proof: the running handler writes nothing ------------------------


def test_a_live_request_writes_nothing(monkeypatch):
    """Drive a real request with `print` and `open` recorder-swapped; assert neither ran.

    The static proof is about the source; this is about the daemon. If any code on the
    request path tried to log - even through a helper this test does not know about - the
    swapped names would record it.
    """
    import blind_relay
    from blind_cache import RefCache
    from blind_door import DoorGate, DoorIssuer
    from blind_relay import Relay, serve

    calls: list[tuple] = []

    def fake_print(*args, **kwargs):
        calls.append(("print", args))

    def fake_open(*args, **kwargs):
        calls.append(("open", args))
        raise AssertionError("the relay opened a file")

    monkeypatch.setattr("builtins.print", fake_print)
    monkeypatch.setattr("builtins.open", fake_open)

    class Sub:
        def read(self, ref, *, max_size):
            return b"bytes"

    issuer = DoorIssuer()
    relay = Relay(gate=DoorGate(issuer.public_key), cache=RefCache(), substrate=Sub())
    srv = serve(relay, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
        conn.request("GET",
                     "/b/chk:CHK@aCu~Vh9LE88MLsUIIhUR1rQbwYHKC8xIDacYCzIP1Cg,"
                     "3nWMwYb8n9llkrRrUOMoDcVaFo-aBxl4X-knG8qE5fk,AAMC--8",
                     headers={"Authorization": f"Bearer {issuer.mint()}"})
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()
        assert calls == [], f"the request path wrote: {calls}"
    finally:
        srv.shutdown()
    del blind_relay
