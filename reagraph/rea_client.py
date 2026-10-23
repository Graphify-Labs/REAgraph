"""Live REA MCP client: pull findings from REA and fold them into the graph.

REAgraph does NOT vendor REA. At runtime this client spawns the REA MCP server
(github.com/morluto/rea) over stdio, initializes a session, lists its tools, runs
the requested analyses, and converts each tool result into a node-link graph
fragment via the sibling ``reagraph.rea_adapter``. The fragments are exactly the
dicts ``reagraph.bridge.ingest_stream`` already accepts, so:

    from reagraph import bridge
    from reagraph.rea_client import ReaClient
    bridge.ingest_stream(ReaClient("app.asar"), "reagraph.json")

folds live REA findings into the persistent graph crash-safely.

Design for testability: the connection (spawn + MCP handshake) is isolated in
``_connect``; the connection-INDEPENDENT logic (iterate tool results -> fragments
via the adapter, fail-open on a bad tool) lives in the async ``collect`` method,
which takes an already-connected session-like object and can be unit-tested with
a tiny fake. ``mcp`` is imported lazily inside ``_connect`` only, so this module
imports fine without ``mcp`` (or node/npx) installed.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from typing import Iterator, Mapping, Sequence

# The adapter is a sibling module that ships in the same wheel, so it is always
# importable here. (``collect`` and ``_cached_only`` already tolerate an empty
# ``SUPPORTED_TOOLS`` and a ``to_fragment`` that raises, so a half-built adapter
# degrades gracefully without needing an import-time stub.)
from . import rea_adapter


# npx-based default: run REA straight from npm with no local checkout. The
# ``--mcp`` flag is what makes REA start its MCP *stdio server* -- the bare CLI
# prints help and exits, so without it the handshake closes on connect. Verified
# against rea-agents (its ``--help`` lists ``--mcp`` as "Start as MCP stdio
# server"). Override the whole command via the constructor or REAGRAPH_REA_CMD.
# Pin the version, matching REA_PIN in cli.py (the Docker setup-rea path).
# An unpinned @latest would execute whatever npm serves that day.
DEFAULT_SERVER_CMD = ["npx", "-y", "rea-agents@6.7.0", "--mcp"]

# Default to REA's static JavaScript/Electron analysis tool (needs no Ghidra or
# native disassembly) -- the one the adapter is grounded on (rea_adapter
# .SUPPORTED_TOOLS). The set is intersected with the server's actual
# ``list_tools`` and the adapter's ``SUPPORTED_TOOLS`` at call time, so a name
# REA does not offer is simply skipped rather than fatal. Override via ``tools=``.
DEFAULT_TOOLS = ("analyze_javascript_application",)

# The argument that carries the target path differs per REA tool. REA's
# ``analyze_javascript_application`` takes ``input_path`` (verified against its
# live input schema: required ``input_path``, "Local filesystem path for
# input."), not the generic ``path``. Tools absent from this map fall back to
# ``path``. A per-tool override via ``tool_args=`` still wins over both.
_TOOL_PATH_ARG = {"analyze_javascript_application": "input_path"}
_DEFAULT_PATH_ARG = "path"


class ReaClient:
    """A ``bridge.ReaSource`` backed by a live REA MCP server over stdio."""

    def __init__(
        self,
        target: str = ".",
        tools: Sequence[str] | None = None,
        *,
        server_cmd: Sequence[str] | None = None,
        tool_args: Mapping[str, Mapping] | None = None,
        cache=None,
        refresh: bool = False,
        cli_cmd: Sequence[str] | None = None,
        cli_timeout: float = 1800.0,
        cli_max_bytes: int = 1024 * 1024 * 1024,
        source_paths: Sequence[str] | None = None,
    ) -> None:
        self.target = target
        self.tools = tuple(tools) if tools is not None else DEFAULT_TOOLS
        # Demand-scoped analysis: when set, REA's analyze_javascript_application is
        # told to acquire and analyze ONLY these exact inventoried file paths
        # (relative to the app root) instead of the whole app -- so re-analyzing a
        # single changed file after a small edit does not re-pay for the entire
        # application. Must be exact inventory paths (no globs/aliases). It becomes
        # part of the cache key, so a scoped analysis is a distinct cache entry.
        self.source_paths = list(source_paths) if source_paths else None
        self.server_cmd = self._resolve_cmd(server_cmd)
        self.tool_args = {k: dict(v) for k, v in (tool_args or {}).items()}
        # Optional content-addressed cache (reagraph.cache.Cache). When set, a
        # (artifact, tool, args) hit skips the REA call entirely; a miss stores
        # the fragment after. refresh=True forces re-analysis past a hit.
        self.cache = cache
        self.refresh = refresh
        # CLI-JSON transport. REA's MCP stdio response has a size budget that a
        # large app's full graph overflows ("resource_constraint ... exceeds the
        # stdio response budget"); REA's CLI emits the complete graph as JSON
        # instead. When ``cli_cmd`` is set, ``findings()`` runs
        # ``<cli_cmd> analyze <target> --format json --full-output`` and maps that,
        # bypassing MCP entirely. ``cli_cmd`` is the REA CLI base (e.g.
        # ["npx","-y","rea-agents@latest"], or a docker run with
        # --entrypoint rea-agents) -- distinct from the MCP ``server_cmd``.
        self.cli_cmd = list(cli_cmd) if cli_cmd else None
        self.cli_timeout = cli_timeout
        # Hard cap on REA CLI stdout. The CLI JSON for a large app is hundreds of
        # MB; ``analyze_cli`` streams it to a temp file (not RAM) and refuses to
        # load more than this many bytes into memory to parse, so a runaway or
        # pathologically large document raises a clean error instead of OOMing.
        self.cli_max_bytes = int(cli_max_bytes)

    # -- construction helpers (no I/O, no process spawn) ------------------

    @staticmethod
    def _resolve_cmd(server_cmd: Sequence[str] | None) -> list[str]:
        """Explicit arg > REAGRAPH_REA_CMD env > npx default. Never spawns."""
        if server_cmd:
            return list(server_cmd)
        env = os.environ.get("REAGRAPH_REA_CMD")
        if env:
            return shlex.split(env)
        return list(DEFAULT_SERVER_CMD)

    def _args_for(self, tool: str) -> dict:
        """Call arguments for a tool: per-tool override, else the target path.

        The path argument name is tool-specific (see ``_TOOL_PATH_ARG``): REA's
        ``analyze_javascript_application`` wants ``input_path``, others default to
        ``path``. Matching is normalization-tolerant so a dashed server id
        ("analyze-javascript-application") still resolves to ``input_path``.
        """
        if tool in self.tool_args:
            return dict(self.tool_args[tool])
        norm = _normalize_tool(tool)
        arg = _TOOL_PATH_ARG_NORM.get(norm, _DEFAULT_PATH_ARG)
        args = {arg: self.target}
        # Scope to specific inventory files for the JS analyzer, when requested.
        if self.source_paths and norm == _ANALYZE_TOOL_NORM:
            args["source_paths"] = list(self.source_paths)
        return args

    # -- ReaSource interface ---------------------------------------------

    def findings(self) -> Iterator[dict]:
        """Yield node-link fragments from a live REA run (bridge.ReaSource)."""
        # CLI-JSON transport: for large apps that overflow REA's MCP stdio budget,
        # analyze via the CLI (complete JSON) instead of the MCP server.
        if self.cli_cmd:
            for fragment in self.analyze_cli():
                yield fragment
            return

        # Fast path: a fully-cached pull needs no REA process at all. If every
        # requested tool is already cached we yield those fragments and RETURN
        # WITHOUT spawning REA or even importing ``mcp`` (the spawn + handshake
        # is ~300ms even when no analysis runs). Any miss (or nothing to
        # pre-resolve) returns None and falls through to the normal
        # connect+collect path, which still serves per-tool hits and caches
        # misses.
        cached = self._cached_only()
        if cached is not None:
            for fragment in cached:
                yield fragment
            return

        # Collected inside the live session, then yielded: the MCP session must
        # stay open while tools run. bridge.ingest_stream still saves after each
        # merge, so crash-safety is preserved as fragments are consumed.
        import asyncio

        for fragment in asyncio.run(self._connect()):
            yield fragment

    def _cached_only(self) -> list[dict] | None:
        """Pre-resolve every requested tool against the cache, no spawn, no mcp.

        Returns the cached fragments (in request order) only when EVERY requested
        tool is already cached, so ``findings`` can serve a fully-cached pull
        without touching REA. Returns None -- i.e. fall through to the live
        connect+collect path -- when the cache is off or refreshing, when there
        are no supported tools to pre-resolve, when any tool misses, or (fail
        open) when the cache raises during the pre-check. Never spawns a process.
        """
        if self.cache is None or self.refresh:
            return None
        supported = set(getattr(rea_adapter, "SUPPORTED_TOOLS", set()) or ())
        # Mirror collect(): intersect with the adapter's supported set when it is
        # non-empty, else pre-resolve every requested tool.
        tools = [t for t in self.tools if (t in supported if supported else True)]
        if not tools:
            return None  # nothing to pre-resolve -> let the normal path run
        try:
            fragments: list[dict] = []
            for tool in tools:
                key = self.cache.key_for(self.target, tool, self._args_for(tool))
                hit = self.cache.get(key)
                if not hit:
                    return None  # a miss -> connect and run (serves other hits)
                fragments.append(hit["fragment"])
            return fragments
        except Exception:  # fail-open: a broken cache never blocks a pull
            return None

    # -- connection-INDEPENDENT logic (unit-tested with a fake session) ---

    async def collect(self, session) -> list[dict]:
        """Run the requested analyses on an already-connected session-like object.

        ``session`` must expose async ``list_tools()`` and ``call_tool(name, args)``
        (the shape of ``mcp.ClientSession``). Returns one fragment per tool that
        succeeded. Fail-open: a tool whose call or conversion raises is logged to
        stderr and skipped, so one failing REA tool never aborts the whole pull.
        """
        available = await self._list_tool_names(session)
        supported = set(getattr(rea_adapter, "SUPPORTED_TOOLS", set()) or ())
        # Tolerant matching: REA's live tool id may use dashes
        # ("analyze-javascript-application") while self.tools / SUPPORTED_TOOLS
        # ground the underscore form. Compare under a normalization that treats
        # '-' and '_' as equivalent and ignores case, but keep the SERVER's
        # actual advertised name for call_tool and the ADAPTER's supported name
        # for to_fragment, so the right id is called and the JAG mapping still
        # applies. Exact-name servers are unaffected.
        available_by_norm = {}
        for name in available:
            available_by_norm.setdefault(_normalize_tool(name), name)
        supported_by_norm = {_normalize_tool(s): s for s in supported}

        fragments: list[dict] = []
        for tool in self.tools:
            norm = _normalize_tool(tool)
            server_name = available_by_norm.get(norm)
            if server_name is None:
                continue  # REA did not offer this tool
            if supported and norm not in supported_by_norm:
                continue  # adapter cannot convert it
            # Name to hand the adapter: its grounded form when it supports this
            # tool, else the requested name (to_fragment fails open regardless).
            adapter_name = supported_by_norm.get(norm, tool)
            args = self._args_for(tool)
            # Cache check: a hit means we never call REA for this artifact+tool.
            # Key on the requested name (stable across dashed/underscored
            # servers and matching _cached_only's pre-check).
            key = None
            if self.cache is not None and not self.refresh:
                try:
                    key = self.cache.key_for(self.target, tool, args)
                    hit = self.cache.get(key)
                except Exception:  # fail-open: a broken cache never blocks a pull
                    key, hit = None, None
                if hit:
                    fragments.append(hit["fragment"])
                    continue
            try:
                result = await session.call_tool(server_name, args)
                payload = _result_payload(result)
            except Exception as exc:  # fail-open: skip one bad tool, keep going
                print(
                    f"reagraph.rea_client: skipped tool {tool}: {exc}",
                    file=sys.stderr,
                )
                continue
            # REA reports a failed analysis as a structured ``{"error": {...}}``
            # envelope in the result body (not an MCP exception, isError unset),
            # e.g. a provider that could not start. That is NOT a finding: folding
            # it would record an opaque evidence node, and caching it would pin the
            # failure as if it were a real analysis. Surface it and skip WITHOUT
            # caching, so a later run (or a fixed environment) re-attempts cleanly.
            rea_err = _rea_error(payload)
            if rea_err is not None:
                print(
                    f"reagraph.rea_client: REA tool {tool} returned an error "
                    f"(not cached): {rea_err}",
                    file=sys.stderr,
                )
                continue
            try:
                fragment = rea_adapter.to_fragment(adapter_name, payload)
            except Exception as exc:  # fail-open: skip one bad tool, keep going
                print(
                    f"reagraph.rea_client: skipped tool {tool}: {exc}",
                    file=sys.stderr,
                )
                continue
            if self.cache is not None:  # populate for next time (best-effort)
                try:
                    k = key if key is not None else self.cache.key_for(self.target, tool, args)
                    self.cache.put(k, fragment, meta={"tool": tool, "target": self.target})
                except Exception:
                    pass
            fragments.append(fragment)
        return fragments

    @staticmethod
    async def _list_tool_names(session) -> set:
        """Tool names the server offers (tolerant of result/list shapes)."""
        listed = await session.list_tools()
        tools = getattr(listed, "tools", listed)
        return {getattr(t, "name", t) for t in tools}

    # -- CLI-JSON transport (no mcp; bypasses the stdio response budget) --

    def _enforce_cli_cap(self, nbytes: int) -> None:
        """Raise a clean RuntimeError if the CLI stdout exceeds ``cli_max_bytes``."""
        if nbytes > self.cli_max_bytes:
            raise RuntimeError(
                f"REA CLI stdout is {nbytes} bytes, over the cli_max_bytes cap of "
                f"{self.cli_max_bytes}; refusing to buffer the whole document in "
                "memory. Raise cli_max_bytes if this output is legitimately that "
                "large."
            )

    def analyze_cli(self) -> list[dict]:
        """Analyze the target via REA's CLI JSON output and map it to a fragment.

        Runs ``<cli_cmd> analyze <target> --format json --full-output``, parses the
        ``{ok, data, meta}`` envelope, and maps ``data`` through the adapter -- the
        same JavaScript Application Graph the MCP tool returns, but delivered as a
        complete JSON document rather than over the size-capped MCP stdio channel.
        Honors the cache (keyed with a ``transport=cli`` scope) and surfaces a REA
        error envelope without caching it, exactly like the MCP path. Returns a
        one-element fragment list, or [] on an analysis error.
        """
        import subprocess
        import tempfile

        tool = "analyze_javascript_application"
        # Scope is part of the cache key so a demand-scoped run is a distinct entry.
        args = {"transport": "cli"}
        if self.source_paths:
            args["source_paths"] = list(self.source_paths)

        key = None
        if self.cache is not None and not self.refresh:
            try:
                key = self.cache.key_for(self.target, tool, args)
                hit = self.cache.get(key)
            except Exception:
                key, hit = None, None
            if hit:
                return [hit["fragment"]]

        # Argument-injection guard. REA's CLI is ``analyze <path> [options]`` with
        # the options AFTER the path. A target beginning with '-' would be read as
        # a REA flag rather than the positional path. A ``--`` separator before the
        # path is NOT viable here: under a standard arg parser everything after
        # ``--`` is positional, so ``analyze -- <path> --format json --full-output``
        # would also swallow the trailing options as positionals and break the
        # command. Normalize instead -- prefix a dashed target with ``./`` so it is
        # an unambiguous relative path ("./-weird.asar"). Absolute paths ('/...')
        # and ordinary relative paths are untouched. The cache key still uses the
        # original self.target, so identity is unchanged.
        safe_target = self.target
        if safe_target.startswith("-"):
            safe_target = os.path.join(".", safe_target)

        cmd = list(self.cli_cmd) + [
            "analyze", safe_target, "--format", "json", "--full-output",
        ]
        for sp in self.source_paths or []:
            cmd += ["--source-path", sp]  # REA's CLI flag (repeatable)

        # Stream the CLI's (potentially hundreds-of-MB) JSON stdout straight to a
        # temp file instead of buffering it in RAM: ``stdout`` is a binary file
        # object, so the OS writes the child's output to disk directly and no
        # ``text=`` second decoded copy is ever made. We then enforce a hard
        # ``cli_max_bytes`` cap BEFORE reading the file back for parsing, so an
        # over-large document raises a clean error instead of exhausting memory.
        # stderr stays captured (bounded) for error messages. The temp file is
        # always removed in the finally.
        tmp = tempfile.NamedTemporaryFile(
            mode="wb", prefix="reagraph-rea-cli-", suffix=".json", delete=False
        )
        tmp_path = tmp.name
        try:
            try:
                result = subprocess.run(
                    cmd, stdout=tmp, stderr=subprocess.PIPE,
                    timeout=self.cli_timeout,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(
                    f"could not launch the REA CLI {cmd[0]!r}: {exc}. Set a "
                    "working REA CLI base via cli_cmd / --rea-cli-cmd (e.g. "
                    "'npx -y rea-agents@latest')."
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"REA CLI {cmd[0]!r} did not finish within "
                    f"cli_timeout={self.cli_timeout}s."
                ) from exc
            finally:
                try:
                    tmp.flush()
                finally:
                    tmp.close()

            # stderr is bytes on a real run (we did not pass text=); a test fake
            # may hand back a str. Decode and bound either way.
            raw_err = getattr(result, "stderr", b"") or b""
            if isinstance(raw_err, bytes):
                stderr_text = raw_err.decode("utf-8", "replace")
            else:
                stderr_text = str(raw_err)
            stderr_text = stderr_text[:8192]
            returncode = getattr(result, "returncode", 0)

            # stdout: a real run streamed it to the temp file (result.stdout is
            # None); a test fake monkeypatching subprocess.run returns it on the
            # result object as a str/bytes. Honor both, and cap either way so we
            # never load more than cli_max_bytes into memory.
            faked_stdout = getattr(result, "stdout", None)
            if isinstance(faked_stdout, (str, bytes)):
                faked_bytes = (
                    faked_stdout.encode("utf-8", "replace")
                    if isinstance(faked_stdout, str) else faked_stdout
                )
                self._enforce_cli_cap(len(faked_bytes))
                stdout_text = faked_bytes.decode("utf-8", "replace")
            else:
                size = os.path.getsize(tmp_path)
                self._enforce_cli_cap(size)
                with open(tmp_path, "r", encoding="utf-8", errors="replace") as fh:
                    stdout_text = fh.read()
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        obj = _parse_cli_json(stdout_text)
        if obj is None:
            detail = (stderr_text or "").strip()[:300]
            raise RuntimeError(
                "REA CLI produced no parseable JSON "
                f"(exit {returncode}){': ' + detail if detail else ''}."
            )

        payload = obj.get("data", obj) if isinstance(obj, dict) else {}
        err = _rea_error(payload)
        if err is None and isinstance(obj, dict):
            err = _rea_error(obj)
        if err is not None:
            print(
                f"reagraph.rea_client: REA CLI analysis returned an error "
                f"(not cached): {err}",
                file=sys.stderr,
            )
            return []

        fragment = rea_adapter.to_fragment(tool, payload)
        if self.cache is not None:
            try:
                k = key if key is not None else self.cache.key_for(self.target, tool, args)
                self.cache.put(k, fragment, meta={"tool": tool, "target": self.target,
                                                  "transport": "cli"})
            except Exception:
                pass
        return [fragment]

    # -- authoritative comparison (REA's own cross-build comparator) ------

    def compare(self, left_target: str, right_target: str) -> dict:
        """Authoritative cross-build diff via REA's ``compare_application_versions``.

        Analyzes both targets and compares them in a single REA MCP session, and
        returns the comparison ``normalized_result`` (map it with
        ``reagraph.compare.to_report``). This is REA's exact-matching comparison --
        the authoritative counterpart to ``reagraph.diff``'s offline signature
        heuristic. Raises a clean RuntimeError if REA is unreachable or an analysis
        or the comparison errors.
        """
        import asyncio

        return asyncio.run(self._compare(left_target, right_target))

    async def _compare(self, left_target: str, right_target: str) -> dict:
        """Spawn REA over stdio and run the comparison (see ``compare``)."""
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise RuntimeError(
                "reagraph.rea_client needs the 'mcp' package to reach REA. "
                "Install it (pip install mcp) and point REAGRAPH_REA_CMD at your "
                "REA MCP server command."
            ) from exc

        params = StdioServerParameters(
            command=self.server_cmd[0], args=list(self.server_cmd[1:])
        )
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await self.compare_on_session(
                        session, left_target, right_target
                    )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"could not launch REA MCP server {self.server_cmd!r}: {exc}. "
                "Install node/npx or set REAGRAPH_REA_CMD."
            ) from exc
        except _HANDSHAKE_ERRORS as exc:
            raise RuntimeError(
                "could not complete the REA MCP handshake for "
                f"{' '.join(self.server_cmd)}: {_first_cause(exc)}. Override the "
                "command with REAGRAPH_REA_CMD."
            ) from exc

    async def compare_on_session(self, session, left_target: str, right_target: str) -> dict:
        """Analyze both targets and compare them on an already-connected session.

        Connection-INDEPENDENT (unit-testable with a fake session): calls
        ``analyze_javascript_application`` on each target (``input_path``) and feeds
        both Evidence envelopes to ``compare_application_versions`` as ``left`` /
        ``right``. Returns the comparison ``normalized_result``. Surfaces a REA
        error on either analysis or the comparison as a clean RuntimeError.
        """
        analyze = "analyze_javascript_application"
        ev_left = _result_payload(await session.call_tool(analyze, {"input_path": left_target}))
        err = _rea_error(ev_left)
        if err is not None:
            raise RuntimeError(f"REA analysis of the left build failed: {err}")
        ev_right = _result_payload(await session.call_tool(analyze, {"input_path": right_target}))
        err = _rea_error(ev_right)
        if err is not None:
            raise RuntimeError(f"REA analysis of the right build failed: {err}")
        result = _result_payload(
            await session.call_tool(
                "compare_application_versions", {"left": ev_left, "right": ev_right}
            )
        )
        err = _rea_error(result)
        if err is not None:
            raise RuntimeError(f"REA comparison failed: {err}")
        if isinstance(result, dict):
            return result.get("normalized_result", result)
        return {}

    # -- connection (lazy mcp import; the only part that spawns a process) -

    async def _connect(self) -> list[dict]:
        """Spawn REA over stdio, handshake, and hand the session to ``collect``."""
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise RuntimeError(
                "reagraph.rea_client needs the 'mcp' package to reach REA. "
                "Install it (pip install mcp) and point REAGRAPH_REA_CMD at your "
                "REA MCP server command (default: "
                f"{' '.join(DEFAULT_SERVER_CMD)})."
            ) from exc

        params = StdioServerParameters(
            command=self.server_cmd[0], args=list(self.server_cmd[1:])
        )
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await self.collect(session)
        except FileNotFoundError as exc:
            # The binary/npx itself is missing: a spawn failure, not a handshake
            # failure. Keep the specific, pre-existing actionable message.
            raise RuntimeError(
                f"could not launch REA MCP server {self.server_cmd!r}: {exc}. "
                "Install node/npx (the default uses 'npx') or set REAGRAPH_REA_CMD "
                "to a working REA MCP server command."
            ) from exc
        except _HANDSHAKE_ERRORS as exc:
            # The server spawned, but the MCP connection/handshake failed: an
            # MCPError, an anyio/asyncio ExceptionGroup (common when the stdio
            # peer closes during initialize), a ConnectionError/OSError, a
            # timeout, or any other error raised during connect/initialize. The
            # raw ExceptionGroup/MCPError traceback is unreadable to a user, so
            # collapse it into one actionable RuntimeError, surfacing the first
            # underlying cause for context.
            cause = _first_cause(exc)
            raise RuntimeError(
                "could not complete the REA MCP handshake for "
                f"{' '.join(self.server_cmd)}: {cause}. The server started but "
                "the MCP connection closed during initialize. Check that the "
                "command actually starts an MCP stdio server (REA may need a "
                "specific subcommand, e.g. an 'mcp' server command, not the bare "
                "CLI), that REA is set up (`rea setup`), and that your Node "
                "version meets REA's requirement. Override the command with "
                "REAGRAPH_REA_CMD."
            ) from exc


# Errors that mean "the server spawned but the MCP connect/handshake failed".
# ``Exception`` already covers MCPError, ConnectionError, OSError (minus the
# FileNotFoundError spawn case handled first), asyncio.TimeoutError, and the
# ``exceptiongroup`` backport's ExceptionGroup (which subclasses Exception). On
# Python 3.11+ a task group may raise a bare ``BaseExceptionGroup`` (BaseException,
# not Exception), so add it when the name exists; guarded so <3.11 stays valid.
_HANDSHAKE_ERRORS: tuple = (Exception,)
try:  # pragma: no cover - the extra arm only exists on Python 3.11+
    _HANDSHAKE_ERRORS = (Exception, BaseExceptionGroup)  # type: ignore[name-defined]
except NameError:  # pragma: no cover - Python < 3.11 has no BaseExceptionGroup
    pass


def _first_cause(exc: BaseException) -> str:
    """Readable message for ``exc``, unwrapping ExceptionGroups to the first leaf.

    A raw ``ExceptionGroup``/``BaseExceptionGroup`` stringifies to an unhelpful
    "(1 sub-exception)" summary, so descend into its first sub-exception (deeply,
    in case groups nest) and return that leaf's message. Plain exceptions pass
    through as ``str(exc)``. Deterministic: always the first branch.
    """
    cur: BaseException = exc
    seen: set[int] = set()
    while True:
        subs = getattr(cur, "exceptions", None)
        if not subs or id(cur) in seen:
            break
        seen.add(id(cur))
        cur = subs[0]
    text = str(cur).strip()
    return text or cur.__class__.__name__


def _normalize_tool(name) -> str:
    """Normalize a tool name for tolerant matching: '-' == '_', case-insensitive.

    Lets REA's dashed live id ("analyze-javascript-application") match the
    adapter's underscore grounding ("analyze_javascript_application").
    """
    return str(name).replace("-", "_").lower()


# ``_TOOL_PATH_ARG`` keyed under the same normalization used for tool matching,
# so a dashed/underscored/mixed-case server id still resolves to the right path
# argument name. Built once at import, after ``_normalize_tool`` is defined.
_TOOL_PATH_ARG_NORM = {_normalize_tool(k): v for k, v in _TOOL_PATH_ARG.items()}

# The JS analyzer tool (normalized), the only tool that takes ``source_paths``.
_ANALYZE_TOOL_NORM = _normalize_tool("analyze_javascript_application")


def _parse_cli_json(text: str):
    """Parse REA CLI ``--format json`` stdout into an object, tolerating noise.

    With ``--format json`` REA writes one JSON document to stdout (progress goes to
    stderr), so the whole text normally parses. As a fallback (in case a progress
    or banner line leaks onto stdout), scan lines and return the last one that
    parses as a JSON object carrying an ``ok``/``data`` envelope. Returns the
    parsed object, or None if nothing parses.
    """
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    best = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict) and ("data" in obj or "ok" in obj):
            best = obj  # keep the last envelope-shaped object
    return best


def _rea_error(payload) -> str | None:
    """A short message if ``payload`` is REA's structured error envelope, else None.

    REA signals a failed operation with a top-level ``error`` object carrying a
    ``code`` and a human ``message`` (and often a ``remediation``), returned as the
    tool result body rather than as an MCP exception. Example (abridged)::

        {"error": {"code": "execution_failure",
                   "message": "Analysis could not complete. Run `rea doctor` ...",
                   "remediation": {"action": "..."}, "details": {...}}}

    Returns ``"<code>: <message>"`` (message trimmed) when that shape is present,
    else None. Best-effort and never raises: a malformed envelope yields None so a
    genuine result is never misread as an error.
    """
    try:
        if not isinstance(payload, dict):
            return None
        err = payload.get("error")
        if not isinstance(err, dict):
            return None
        code = err.get("code")
        message = err.get("message")
        if message is None and code is None:
            return None
        msg = str(message).strip() if message is not None else ""
        if len(msg) > 300:
            msg = msg[:299] + "…"
        if code and msg:
            return f"{code}: {msg}"
        return str(code) if code else msg
    except Exception:
        return None


def _result_payload(result) -> dict:
    """Normalize an MCP tool result into the plain dict the adapter expects.

    Plain dicts (fakes, already-decoded results) pass through. An ``mcp``
    ``CallToolResult`` is reduced to its structured content, else the first text
    block parsed as JSON, else an empty dict.
    """
    if isinstance(result, dict):
        return result
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    for block in getattr(result, "content", None) or ():
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except (ValueError, TypeError):
                return {"text": text}
    return {}
