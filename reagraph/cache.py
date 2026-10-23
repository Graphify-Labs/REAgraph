"""Content-addressed cache for analysis results (node-link graph fragments).

The expensive thing in REAgraph is *analysis*: running a tool over an artifact to
produce a graph fragment. The same artifact analysed the same way always yields
the same fragment, so we should never pay for it twice. This module keys a stored
fragment by the artifact's content hash plus the analysis *scope* (which tool,
which args, which extractor version). That makes the cache:

  - content-addressed: the key is derived from the artifact's bytes
    (`artifact.artifact_id`), not its path -- a file that merely moved still hits.
  - scope-aware: a different tool / args / version is a different entry, so one
    analysis never masks another, and a tool upgrade invalidates cleanly.
  - fail-open: a missing OR corrupt entry is simply a miss (returns None, logs to
    stderr). A bad cache is never fatal to a build.

The backend is pluggable (`CacheBackend`). Today the only one is
`LocalCacheBackend` (files under a cache dir); a shared/remote backend can drop in
behind the same tiny interface without touching callers.

Pure stdlib.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Iterable

# Bumped if the on-disk payload shape changes, so stale-shape entries are a miss.
SCHEMA = "reagraph.cache/1"

from . import artifact


def _log(msg: str) -> None:
    """Fail-open diagnostics: never raise, just note it on stderr."""
    print(f"[reagraph.cache] {msg}", file=sys.stderr)


def _canonical_json(obj) -> str:
    """Stable JSON so equal args always hash the same, regardless of dict order."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _value_sha256(fragment) -> str:
    """sha256 hex of the canonical JSON of a fragment -- the stored value's own
    digest, recorded on `put` and re-checked on `get`."""
    return hashlib.sha256(_canonical_json(fragment).encode("utf-8")).hexdigest()


class CacheBackend:
    """The pluggable storage contract. Keys are opaque strings; values are bytes.

    A backend is a dumb byte store -- it knows nothing about fragments or JSON.
    That keeps the interface small enough that a remote/shared backend is a drop-in.
    """

    def get(self, key: str) -> bytes | None:
        raise NotImplementedError

    def put(self, key: str, value: bytes) -> None:
        raise NotImplementedError

    def keys(self) -> Iterable[str]:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError


def _default_cache_dir() -> Path:
    env = os.environ.get("REAGRAPH_CACHE")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "reagraph"


class LocalCacheBackend(CacheBackend):
    """Each entry is one file under a cache dir, sharded by key prefix (ab/cdef...)
    to avoid one huge flat directory. Writes are atomic (tmp file + os.replace)."""

    def __init__(self, directory=None):
        self.dir = Path(directory) if directory is not None else _default_cache_dir()

    # -- path layout ------------------------------------------------------
    def _path(self, key: str) -> Path:
        # Keys are sha256 hex digests (see Cache.key_for). Reject anything
        # that could act as a path segment: a key handed back by a remote
        # cache backend must never escape the cache dir.
        if "/" in key or "\\" in key or key in (".", ".."):
            raise ValueError(f"invalid cache key: {key!r}")
        # Shard on the first two chars; the rest is the filename.
        safe = key if len(key) >= 3 else f"_{key}_"
        return self.dir / safe[:2] / (safe[2:] + ".json")

    # -- CacheBackend -----------------------------------------------------
    def get(self, key: str) -> bytes | None:
        p = self._path(key)
        try:
            return p.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            _log(f"read failed for {key}: {exc}")
            return None

    def put(self, key: str, value: bytes) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Unique tmp name in the same dir so os.replace is atomic on the FS.
        tmp = p.parent / f".{p.name}.{os.getpid()}.{time.time_ns()}.tmp"
        try:
            tmp.write_bytes(value)
            os.replace(tmp, p)
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass

    def keys(self) -> Iterable[str]:
        if not self.dir.exists():
            return
        for shard in sorted(self.dir.iterdir()):
            if not shard.is_dir():
                continue
            for entry in sorted(shard.glob("*.json")):
                yield shard.name + entry.stem

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            _log(f"delete failed for {key}: {exc}")

    def __len__(self) -> int:
        return sum(1 for _ in self.keys())


class Cache:
    """Content-addressed store of analysis results, over a pluggable backend.

    Callers derive a key with `key_for(...)`, then `get`/`put` fragments. The
    payload on disk is `{"fragment": ..., "meta": {...}}`.
    """

    def __init__(self, backend: CacheBackend | None = None):
        self.backend = backend if backend is not None else LocalCacheBackend()

    def key_for(
        self,
        artifact_path,
        tool: str = "",
        args=None,
        *,
        extractor_version: str = "",
    ) -> str:
        """Deterministic key over the artifact's content id + the analysis scope.

        key = sha256( artifact_id(path) | tool | canonical-json(args) | version ).
        Keying on tool+args+version means a different analysis of the same
        artifact is a distinct entry, and a tool upgrade invalidates cleanly.
        """
        aid = artifact.artifact_id(os.fspath(artifact_path))
        parts = [
            str(aid),
            tool or "",
            _canonical_json(args),
            extractor_version or "",
        ]
        payload = "\x00".join(parts).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def get(self, key: str) -> dict | None:
        """Return the stored {"fragment", "meta"} payload, or None on miss.

        Never raises: a missing OR corrupt entry is just a miss (logged).

        Value integrity: if the stored meta carries a ``value_sha256`` (written by
        `put`), the fragment is re-hashed on load and compared against it; a
        mismatch -- corruption, truncation, or tampering of the stored value
        against its OWN recorded digest -- is treated as a corrupt miss (None).
        Older entries written before this check existed carry no ``value_sha256``
        and still load (back-compat). This is a SELF-hash, so it detects a value
        that no longer matches the digest stored next to it; it does NOT
        authenticate the writer -- a malicious or buggy server that stores a
        consistent (fragment, value_sha256) pair passes this check. The shared
        tier therefore remains a trust boundary (see remote_cache.TieredBackend).
        """
        raw = self.backend.get(key)
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            _log(f"corrupt entry {key} ignored: {exc}")
            return None
        if not isinstance(payload, dict) or "fragment" not in payload:
            _log(f"entry {key} has an unexpected shape; ignoring")
            return None
        meta = payload.get("meta")
        if isinstance(meta, dict):
            recorded = meta.get("value_sha256")
            if recorded is not None:
                actual = _value_sha256(payload["fragment"])
                if actual != recorded:
                    _log(
                        f"value integrity mismatch for {key} "
                        f"(recorded {recorded}, got {actual}); treating as corrupt"
                    )
                    return None
        return payload

    def put(self, key: str, fragment: dict, meta: dict | None = None) -> None:
        """Store a fragment plus its meta, stamping created_at + a schema tag.

        A ``value_sha256`` digest of the canonical JSON of the fragment is recorded
        in meta so `get` can detect later corruption/truncation/tampering of the
        stored value against its own digest. See `get` for the (deliberate) limit:
        it is a self-hash, not writer authentication.
        """
        full_meta = dict(meta or {})
        full_meta.setdefault("created_at", time.time())
        full_meta["schema"] = SCHEMA
        full_meta["value_sha256"] = _value_sha256(fragment)
        payload = {"fragment": fragment, "meta": full_meta}
        self.backend.put(key, _canonical_json(payload).encode("utf-8"))

    def stats(self) -> dict:
        """{entries, bytes, dir} -- entry count, total stored bytes, cache dir."""
        entries = 0
        total_bytes = 0
        for key in self.backend.keys():
            entries += 1
            raw = self.backend.get(key)
            if raw is not None:
                total_bytes += len(raw)
        directory = getattr(self.backend, "dir", None)
        return {
            "entries": entries,
            "bytes": total_bytes,
            "dir": str(directory) if directory is not None else None,
        }

    def clear(self) -> int:
        """Wipe all entries; return how many were removed."""
        removed = 0
        for key in list(self.backend.keys()):
            self.backend.delete(key)
            removed += 1
        return removed
