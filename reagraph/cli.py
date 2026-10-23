"""reagraph CLI: add findings to persistent memory, diff builds, show stats.

    reagraph add <finding.jag.json> [--graph reagraph.json]
    reagraph diff <a.json> <b.json>
    reagraph stats [--graph reagraph.json]
    reagraph summary [--graph reagraph.json] [--top N]       # bounded map of a big graph
    reagraph coverage [--graph reagraph.json]                # what's verified vs unverified
    reagraph query "<question>" [--graph reagraph.json]      # delegates to graphify
    reagraph serve [--graph reagraph.json]                   # run the MCP server
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys

from . import coverage as coveragemod
from . import diff as diffmod
from . import memory
from . import summarize as summarizemod
from .ingest import load_any

DEFAULT_GRAPH = "reagraph.json"

# Pinned REA version (kept in lockstep with examples/rea-docker/Dockerfile and the
# Graphify-Labs/rea mirror tag reagraph-pin-6.7.0). `setup-rea` builds this image.
REA_PIN = "6.7.0"
REA_IMAGE = f"reagraph-rea:{REA_PIN}"


def _cmd_setup_rea(args) -> int:
    # Build a local REA MCP-server image so a user never has to touch the external
    # REA repo or hand-assemble a docker command. Uses the pinned rea-agents from
    # the Graphify-Labs mirror lineage; no REA source is vendored. Pure `docker`
    # calls (install+commit -- buildx-independent, the verified-reliable path).
    if not shutil.which("docker"):
        print("docker not found. Install Docker Desktop or `colima start`, then "
              "re-run `reagraph setup-rea`.", file=sys.stderr)
        return 1
    if subprocess.call(["docker", "info"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0:
        print("the Docker daemon is not running. Start Docker Desktop (or "
              "`colima start`) and re-run `reagraph setup-rea`.", file=sys.stderr)
        return 1

    built = subprocess.call(["docker", "image", "inspect", REA_IMAGE],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    if built and not args.rebuild:
        print(f"{REA_IMAGE} is already built (use --rebuild to rebuild).")
    else:
        print(f"building {REA_IMAGE} (installs pinned REA {REA_PIN}; takes a few "
              "minutes the first time)...")
        name = "reagraph_rea_build"
        subprocess.call(["docker", "rm", "-f", name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        install = (
            "apt-get update >/dev/null 2>&1 && "
            "apt-get install -y --no-install-recommends procps >/dev/null 2>&1 && "
            f"npm install -g rea-agents@{REA_PIN}"
        )
        rc = subprocess.call(["docker", "run", "--name", name, "node:24-slim",
                              "sh", "-c", install])
        if rc != 0:
            print("REA install failed inside the container (see output above).",
                  file=sys.stderr)
            subprocess.call(["docker", "rm", "-f", name],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return 1
        subprocess.call(["docker", "commit", "--change",
                         'ENTRYPOINT ["rea-agents","--mcp"]', name, REA_IMAGE],
                        stdout=subprocess.DEVNULL)
        subprocess.call(["docker", "tag", REA_IMAGE, "reagraph-rea:latest"])
        subprocess.call(["docker", "rm", "-f", name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"built {REA_IMAGE} (also tagged reagraph-rea:latest).")

    # Emit the ready-to-use command. The artifact dir is mounted at /work, so the
    # pull target is an in-container /work/<file> path.
    rea_cmd = f'docker run --rm -i -v "$PWD":/work:ro {REA_IMAGE}'
    print("\nREA is ready. From the directory holding your app (ASAR or extracted JS):")
    print(f"  export REAGRAPH_REA_CMD='{rea_cmd}'")
    print("  reagraph pull /work/app.asar --graph reagraph.json")
    print("  # large app? add --rea-cli-cmd "
          f"'docker run --rm -v \"$PWD\":/work:ro --entrypoint rea-agents {REA_IMAGE}'")
    print("  reagraph doctor   # to re-check prerequisites")
    return 0


def _cmd_add(args) -> int:
    before = memory.stats(memory.load(args.graph))
    graph = memory.load(args.graph)
    for f in args.files:
        memory.merge(graph, load_any(f))
    memory.save(graph, args.graph)
    after = memory.stats(graph)
    print(
        f"merged {len(args.files)} finding(s) into {args.graph}: "
        f"nodes {before['nodes']}->{after['nodes']}, edges {before['edges']}->{after['edges']}"
    )
    return 0


def _cmd_diff(args) -> int:
    a = load_any(args.a)
    b = load_any(args.b)
    # Node identity regime. REA node_ids are not stable across builds, so diffing
    # two REA builds by id reports the whole app as changed; matching by a
    # build-stable signature (kind + range-normalized label + source file) fixes
    # that. Default 'auto': use the signature when the graphs look like REA graphs
    # (any node carries rea_kind), else id-key (correct for graphify/stable-id).
    mode = getattr(args, "by", "auto")

    def _is_rea(g):
        return any(n.get("rea_kind") for n in g.get("nodes", []) if isinstance(n, dict))

    if mode == "auto":
        mode = "signature" if (_is_rea(a) or _is_rea(b)) else "id"
    signature = diffmod.rea_signature if mode == "signature" else None
    if mode == "signature":
        print("(matching by build-stable signature: kind + label + source file)")
    print(diffmod.format_report(diffmod.diff(a, b, signature=signature)))
    return 0


def _cmd_compare(args) -> int:
    # Authoritative cross-build diff: delegate to REA's own
    # compare_application_versions (exact matching), vs `diff`'s offline signature
    # heuristic. Analyzes both builds and compares them in one REA session.
    from . import compare as comparemod
    from . import rea_client
    cmd = shlex.split(args.rea_cmd) if args.rea_cmd else None
    client = rea_client.ReaClient(server_cmd=cmd)
    nr = client.compare(args.left, args.right)
    report = comparemod.to_report(nr)
    print(comparemod.format_report(report))
    if args.save:
        import json
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump({"normalized_result": nr, "report": report}, f, indent=1)
        print(f"saved comparison to {args.save}")
    return 0


def _cmd_stats(args) -> int:
    s = memory.stats(memory.load(args.graph))
    print(f"{args.graph}: {s['nodes']} nodes, {s['edges']} edges")
    print(f"  edge confidence: {s['edge_confidence']}")
    return 0


def _cmd_summary(args) -> int:
    graph = memory.load(args.graph)
    print(summarizemod.format_summary(summarizemod.summarize(graph, top=args.top)))
    return 0


def _cmd_coverage(args) -> int:
    print(coveragemod.gaps_report(memory.load(args.graph)))
    return 0


def _cmd_pull(args) -> int:
    # Connect to a running/spawned REA MCP server, analyze the target, and fold
    # each finding into the graph as it arrives (crash-safe, fail-open). By
    # default a content-addressed cache serves a repeat analysis with no REA call.
    from . import bridge, rea_client
    cmd = shlex.split(args.rea_cmd) if args.rea_cmd else None
    cli_cmd = shlex.split(args.rea_cli_cmd) if getattr(args, "rea_cli_cmd", None) else None
    cache = None
    if not args.no_cache:
        from . import cache as cachemod
        cache = cachemod.Cache()
    if cli_cmd:
        print("(CLI-JSON transport: bypasses REA's MCP stdio size budget for large apps)")
    client = rea_client.ReaClient(target=args.target, server_cmd=cmd, cache=cache,
                                  refresh=args.refresh, cli_cmd=cli_cmd,
                                  source_paths=getattr(args, "source_path", None) or None)
    s = bridge.ingest_stream(client, args.graph)
    print(f"pulled from REA into {args.graph}: {s['nodes']} nodes, {s['edges']} edges "
          f"(EXTRACTED {s['edge_confidence']['EXTRACTED']} / INFERRED {s['edge_confidence']['INFERRED']})")
    return 0


def _cmd_attest(args) -> int:
    # Does the shipped artifact match the source? Structural source<->binary diff.
    from . import attest
    src = memory.load(args.source)
    shipped = memory.load(args.shipped)
    print(attest.format_report(attest.attest(src, shipped, min_confidence=args.min_confidence)))
    return 0


def _cmd_cache(args) -> int:
    from . import cache as cachemod
    c = cachemod.Cache()
    if args.action == "clear":
        n = c.clear()
        print(f"cleared {n} cache entries from {c.stats()['dir']}")
    else:
        st = c.stats()
        print(f"cache: {st['entries']} entries, {st['bytes']} bytes at {st['dir']}")
    return 0


def _cmd_doctor(args) -> int:
    from . import doctor
    print(doctor.report())
    return 0 if doctor.ready() else 1


def _cmd_serve(args) -> int:
    # The MCP server resolves its graph via REAGRAPH_GRAPH; forward --graph.
    os.environ["REAGRAPH_GRAPH"] = args.graph
    from . import serve  # lazy: pulls in mcp only when actually serving
    return serve.main()


def _cmd_serve_cache(args) -> int:
    from . import cache_server
    # Tokens are sourced from the environment ONLY (never a CLI arg: argv leaks
    # via `ps`), mirroring cache_server.main's posture.
    read_token = os.environ.get(cache_server.ENV_READ_TOKEN) or None
    write_token = os.environ.get(cache_server.ENV_WRITE_TOKEN) or None
    cache_server.serve(
        host=args.host,
        port=args.port,
        directory=args.dir,
        read_token=read_token,
        write_token=write_token,
        max_value_bytes=int(args.max_value_mb * 1024 * 1024),
        validate_payload=not args.no_validate_payload,
    )
    return 0


def _cmd_demo(args) -> int:
    # The killer demo, offline: two REAL rea-agents analyses of the same Electron
    # app one build apart (an exfil endpoint was added). REA keys nodes by a
    # per-build hash, so a raw id-diff drowns the real change in churn; reagraph
    # matches by meaning. Graphs ship in the wheel -- no REA/Docker/network.
    import json
    from importlib import resources

    try:
        pkg = resources.files("reagraph").joinpath("demo")
        a = json.loads(pkg.joinpath("base.json").read_text(encoding="utf-8"))
        b = json.loads(pkg.joinpath("feat.json").read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"could not load the bundled demo graphs: {exc}", file=sys.stderr)
        return 1

    n = len([x for x in a.get("nodes", []) if isinstance(x, dict)])
    raw = diffmod.diff(a, b)  # id mode (what a naive / byte-offset diff sees)
    sig = diffmod.diff(a, b, signature=diffmod.rea_signature)  # match by meaning
    rs, ss = raw["summary"], sig["summary"]
    raw_changed = rs["nodes_added"] + rs["nodes_removed"]
    real_changed = ss["nodes_added"] + ss["nodes_removed"]

    def _describe(sig_key):  # "kind|label|source#ord" -> readable
        s = str(sig_key).rsplit("#", 1)[0]
        parts = s.split("|")
        kind = parts[0] if parts else "?"
        label = parts[1] if len(parts) > 1 else ""
        src = parts[2] if len(parts) > 2 else ""
        return kind, label, src

    print("reagraph demo — two real REA analyses of the same app, one build apart.")
    print("(An exfil endpoint was added. REA identifies nodes by a per-build hash,")
    print(" so a raw id-diff drowns the real change in churn; reagraph matches by meaning.)")
    print()
    print(f"  REA raw id-diff :  {raw_changed} of {n} nodes \"changed\"   <- the #4520 problem")
    print(f"  reagraph diff   :  {real_changed} changed")
    print()
    if sig["nodes_added"] or sig["nodes_removed"]:
        print("  The real delta:")
        for k in sig["nodes_added"]:
            kind, label, src = _describe(k)
            print(f"    + {kind}  \"{label}\"  {src}")
        for k in sig["nodes_removed"]:
            kind, label, src = _describe(k)
            print(f"    - {kind}  \"{label}\"  {src}")
    print()
    print("Byte-agnostic version diff, validated on real REA output (F1=1.00, zero")
    print("spurious). Try it on your own builds:")
    print("    reagraph diff build-a.json build-b.json      # auto-detects REA graphs")
    print("    reagraph setup-rea && reagraph pull app.asar # analyze live")
    return 0


def _cmd_install_skill(args) -> int:
    # Drop the packaged agent skill into a skills directory so an agent/CLI picks
    # it up (the same idea as installing the graphify skill). Works from an
    # installed wheel or a source checkout via importlib.resources.
    from pathlib import Path
    try:
        from importlib import resources
        text = resources.files("reagraph").joinpath("skill/SKILL.md").read_text(encoding="utf-8")
    except Exception as exc:
        print(f"could not locate the packaged reagraph skill: {exc}", file=sys.stderr)
        return 1
    dest_dir = Path(args.dir).expanduser() / "reagraph"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "SKILL.md"
    dest.write_text(text, encoding="utf-8")
    print(f"installed the reagraph skill -> {dest}")
    print("trigger it with /reagraph (restart your agent/CLI if it was already open)")
    return 0


def _cmd_query(args) -> int:
    if not shutil.which("graphify"):
        print("graphify is not installed; install it to query the graph:\n"
              "  uv tool install graphifyy   # then: graphify query ... --graph " + args.graph,
              file=sys.stderr)
        return 1
    return subprocess.call(["graphify", "query", args.question, "--graph", args.graph])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reagraph", description="Persistent graph memory for reverse engineering.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="fold finding(s) into persistent memory")
    a.add_argument("files", nargs="+", help="REA JAG JSON or node-link graph file(s)")
    a.add_argument("--graph", default=DEFAULT_GRAPH)
    a.set_defaults(func=_cmd_add)

    d = sub.add_parser("diff", help="structural (byte-agnostic) diff of two graphs")
    d.add_argument("a")
    d.add_argument("b")
    d.add_argument("--by", choices=["auto", "id", "signature"], default="auto",
                   help="node identity for matching: 'signature' (build-stable, for "
                        "two REA builds), 'id' (stable-id graphs), or 'auto' (default)")
    d.set_defaults(func=_cmd_diff)

    cm = sub.add_parser("compare",
                        help="authoritative cross-build diff via REA's "
                             "compare_application_versions (analyzes both builds)")
    cm.add_argument("left", help="left build: an ASAR / extracted JS app for REA to analyze")
    cm.add_argument("right", help="right build")
    cm.add_argument("--rea-cmd", default=None,
                    help="override the REA MCP server command (else $REAGRAPH_REA_CMD)")
    cm.add_argument("--save", default=None, help="write the full comparison + report JSON here")
    cm.set_defaults(func=_cmd_compare)

    s = sub.add_parser("stats", help="show accumulated-graph coverage")
    s.add_argument("--graph", default=DEFAULT_GRAPH)
    s.set_defaults(func=_cmd_stats)

    sm = sub.add_parser("summary", help="bounded map (god nodes + clusters) of a big graph")
    sm.add_argument("--graph", default=DEFAULT_GRAPH)
    sm.add_argument("--top", type=int, default=20)
    sm.set_defaults(func=_cmd_summary)

    cv = sub.add_parser("coverage", help="what's observed vs inferred vs unverified (honest gaps)")
    cv.add_argument("--graph", default=DEFAULT_GRAPH)
    cv.set_defaults(func=_cmd_coverage)

    q = sub.add_parser("query", help="query the graph (delegates to graphify)")
    q.add_argument("question")
    q.add_argument("--graph", default=DEFAULT_GRAPH)
    q.set_defaults(func=_cmd_query)

    pl = sub.add_parser("pull", help="connect to REA, analyze a target, fold findings into the graph")
    pl.add_argument("target", help="what REA should analyze (e.g. an unpacked app dir or file)")
    pl.add_argument("--rea-cmd", default=None,
                    help="override the REA MCP server command (else $REAGRAPH_REA_CMD, else npx rea-agents)")
    pl.add_argument("--rea-cli-cmd", default=None,
                    help="analyze via the REA CLI (JSON) instead of MCP -- for large apps that "
                         "overflow REA's MCP stdio budget. Value is the REA CLI base, e.g. "
                         "'npx -y rea-agents@6.7.0'")
    pl.add_argument("--graph", default=DEFAULT_GRAPH)
    pl.add_argument("--no-cache", action="store_true", help="always call REA, do not use the cache")
    pl.add_argument("--refresh", action="store_true", help="re-analyze and overwrite cached results")
    pl.add_argument("--source-path", action="append", default=None,
                    help="demand-scope: analyze ONLY this exact inventory file path "
                         "(relative to the app root); repeat for several. Avoids "
                         "re-analyzing the whole app after a small change.")
    pl.set_defaults(func=_cmd_pull)

    at = sub.add_parser("attest", help="does the shipped artifact match the source? structural source<->binary diff")
    at.add_argument("--source", required=True, help="graphify source graph (graph.json)")
    at.add_argument("--shipped", required=True, help="REAgraph graph of the shipped artifact")
    at.add_argument("--min-confidence", type=float, default=0.5, help="alignment confidence floor (abstain below)")
    at.set_defaults(func=_cmd_attest)

    ca = sub.add_parser("cache", help="inspect or clear the content-addressed analysis cache")
    ca.add_argument("action", nargs="?", choices=["stats", "clear"], default="stats")
    ca.set_defaults(func=_cmd_cache)

    dc = sub.add_parser("doctor", help="check prerequisites for live `reagraph pull` (mcp / node / REA)")
    dc.set_defaults(func=_cmd_doctor)

    sv = sub.add_parser("serve", help="run the REAgraph MCP server (needs the 'mcp' package)")
    sv.add_argument("--graph", default=DEFAULT_GRAPH)
    sv.set_defaults(func=_cmd_serve)

    sc = sub.add_parser("serve-cache",
                        help="run the shared analysis-cache HTTP server "
                             "(tokens from $REAGRAPH_CACHE_READ_TOKEN / _WRITE_TOKEN)")
    sc.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    sc.add_argument("--port", type=int, default=8787, help="bind port (default 8787)")
    sc.add_argument("--dir", default=None,
                    help="store directory (default $REAGRAPH_CACHE_SERVER_DIR or the cache default)")
    sc.add_argument("--max-value-mb", type=float, default=5.0,
                    help="reject uploads larger than this many MiB (default 5)")
    sc.add_argument("--no-validate-payload", action="store_true",
                    help="accept any bytes (skip the reagraph cache-entry shape check)")
    sc.set_defaults(func=_cmd_serve_cache)

    ik = sub.add_parser("install-skill",
                        help="install the reagraph agent skill into ~/.claude/skills (or --dir)")
    ik.add_argument("--dir", default="~/.claude/skills",
                    help="skills directory (default ~/.claude/skills)")
    ik.set_defaults(func=_cmd_install_skill)

    dm = sub.add_parser("demo",
                        help="show the byte-agnostic diff on bundled real-REA graphs "
                             "(no REA/Docker needed)")
    dm.set_defaults(func=_cmd_demo)

    sr = sub.add_parser("setup-rea",
                        help="build a local REA MCP-server Docker image (pinned) and "
                             "print the ready-to-use --rea-cmd; no REA repo needed")
    sr.add_argument("--rebuild", action="store_true", help="rebuild even if the image exists")
    sr.set_defaults(func=_cmd_setup_rea)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
