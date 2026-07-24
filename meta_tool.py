#!/usr/bin/env python3
"""Decrypt and query the Umamusume `meta` asset-index database (offline asset RE).

The game ships `meta` (the asset index: name -> bundle hash) encrypted with SQLite3 Multiple Ciphers
(ChaCha20). `master.mdb` (gameplay tables) is plain SQLite and needs none of this. This tool decrypts
a COPY of `meta` and lets you look assets up by name — e.g. resolve a `cutin_file_id` from
master.mdb's `idle_single_mode_training_cut` to its real `3d/cutt/...` bundle path, entirely offline.

The decryption is: take the server's DB key, XOR each byte with DB_BASE_KEY[i % 13], and open with
ChaCha20 using that as the raw key. Keys are public (published in katboi01/UmaViewer); reimplemented
here, not copied. The Global key differs from JP — pick with --server (default global).

Requires apsw-sqlite3mc (a prebuilt apsw with SQLite3MC):  pip install apsw-sqlite3mc

SAFETY: never opens or writes the live `meta` in place — always works on a copy, and refuses to
write output onto the live file.

  python meta_tool.py find cutt/               # asset names containing "cutt/"
  python meta_tool.py find 101011              # the Speed-lv1 training cut-in id
  python meta_tool.py cutin 101011             # convenience: assets whose name contains the id
  python meta_tool.py tables                   # tables + the 'a' index schema + row count
  python meta_tool.py sql "SELECT n,h FROM a WHERE n LIKE 'sound/%' LIMIT 20"
  python meta_tool.py decrypt --out meta_decrypted   # write a plain (stdlib-readable) copy
  python meta_tool.py --server jp find live/   # use the JP key + JP meta instead
"""
import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

# ── keys (public, from katboi01/UmaViewer Config.cs; verified 2026-07-24 against the live Global meta) ──
# Only the first 13 bytes of the base key are ever used (i % 13).
DB_BASE_KEY = bytes.fromhex("F170CEA4DFCEA3E1A5D8C70BD1000000")
# Global (Steam / EN) — 33 bytes.
GLOBAL_DB_KEY = bytes.fromhex("36236b4c2a3921755226327625503f355d77586d4071385e4c3128742959372453")
# JP (DMM) — 32 bytes.
JP_DB_KEY = bytes.fromhex("6d5b65336336632554712d73505363386d34377b356370233734532973433633")

CIPHER = "chacha20"  # SQLite3MC scheme used by both servers' meta


def derive_key(db_key: bytes, base_key: bytes = DB_BASE_KEY) -> bytes:
    """The game's key transform: XOR each key byte with base_key cycled over its first 13 bytes."""
    k = bytearray(db_key)
    for i in range(len(k)):
        k[i] ^= base_key[i % 13]
    return bytes(k)


def _key_for(server: str) -> bytes:
    return GLOBAL_DB_KEY if server == "global" else JP_DB_KEY


def locate_meta(server: str) -> Path:
    """Best-effort path to the live encrypted `meta`. Override with --meta or TRACKSIDE_META."""
    env = os.environ.get("TRACKSIDE_META")
    if env:
        return Path(env)
    # Both clients write under LocalLow\Cygames\Umamusume on this machine; if you run separate
    # installs, pass --meta explicitly.
    home = Path(os.environ.get("USERPROFILE", Path.home()))
    return home / "AppData" / "LocalLow" / "Cygames" / "Umamusume" / "meta"


def _require_apsw():
    try:
        import apsw  # noqa: F401
    except ImportError:
        sys.exit("apsw not found. Install the SQLite3MC build:  pip install apsw-sqlite3mc")
    import apsw

    try:
        c = apsw.Connection(":memory:")
        c.pragma("cipher", CIPHER)
        c.close()
    except Exception:
        sys.exit(
            "Your apsw lacks SQLite3 Multiple Ciphers. Replace it:\n"
            "  pip uninstall apsw  &&  pip install apsw-sqlite3mc"
        )
    return apsw


def _copy_to_temp(meta: Path) -> Path:
    """Copy the live meta to a private temp file so we never open/lock/modify the original."""
    if not meta.exists():
        sys.exit(f"meta not found: {meta}\n(pass --meta <path> or set TRACKSIDE_META)")
    fd, tmp = tempfile.mkstemp(prefix="meta_", suffix=".db")
    os.close(fd)
    shutil.copy2(meta, tmp)
    return Path(tmp)


class Meta:
    """A decrypted, read-only handle to a COPY of meta. Use as a context manager."""

    def __init__(self, server: str, meta_path: Path):
        self.apsw = _require_apsw()
        self.server = server
        self._src = meta_path
        self._tmp = None
        self.conn = None

    def __enter__(self):
        self._tmp = _copy_to_temp(self._src)
        self.conn = self.apsw.Connection(str(self._tmp))
        self.conn.pragma("cipher", CIPHER)
        self.conn.pragma("hexkey", derive_key(_key_for(self.server)).hex())
        # Fail loudly here (wrong key/cipher) rather than on the first query.
        status = next(self.conn.cursor().execute("PRAGMA quick_check"))[0]
        if status != "ok":
            raise RuntimeError(f"decrypt/integrity check failed: {status!r} (wrong key for {self.server}?)")
        return self

    def __exit__(self, *exc):
        try:
            if self.conn:
                self.conn.close()
        finally:
            if self._tmp and self._tmp.exists():
                os.remove(self._tmp)

    def query(self, sql: str, params=()):
        return list(self.conn.cursor().execute(sql, params))


def cmd_find(m: Meta, args):
    rows = m.query("SELECT n, h FROM a WHERE n LIKE ? ORDER BY n LIMIT ?", (f"%{args.pattern}%", args.limit))
    for name, h in rows:
        print(f"{h}\t{name}")
    print(f"-- {len(rows)} match(es){' (limited)' if len(rows) == args.limit else ''}", file=sys.stderr)


def cmd_cutin(m: Meta, args):
    args.pattern, args.limit = str(args.cutin_id), 100
    cmd_find(m, args)


def cmd_tables(m: Meta, args):
    tables = [r[0] for r in m.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    print("tables:", ", ".join(tables))
    if "a" in tables:
        cols = [r[1] for r in m.query("PRAGMA table_info('a')")]
        n = m.query("SELECT count(*) FROM a")[0][0]
        print(f"'a' (asset index): {n:,} rows; columns: {', '.join(cols)}")
        print("  (n = asset name/path, h = bundle hash)")


def cmd_sql(m: Meta, args):
    low = args.query.lstrip().lower()
    if not (low.startswith("select") or low.startswith("pragma") or low.startswith("with")):
        sys.exit("refusing: only read-only SELECT/PRAGMA/WITH queries are allowed.")
    for row in m.query(args.query):
        print("\t".join("" if v is None else str(v) for v in row))


def cmd_decrypt(m: Meta, args):
    """Write a PLAIN (unencrypted, stdlib-sqlite3-readable) copy of meta to --out."""
    out = Path(args.out).resolve()
    if out == m._src.resolve():
        sys.exit("refusing to overwrite the live meta. Choose a different --out.")
    # m has already opened+verified a decrypted temp copy; rekey it to empty (= strip encryption),
    # then hand that plain file to the output path.
    m.conn.pragma("rekey", "")
    m.conn.close()
    m.conn = None
    shutil.move(str(m._tmp), str(out))
    m._tmp = None
    print(f"wrote plain decrypted meta -> {out}")


def main():
    ap = argparse.ArgumentParser(description="Decrypt & query the Umamusume meta asset index.")
    ap.add_argument("--server", choices=["global", "jp"], default="global", help="which key/meta (default global)")
    ap.add_argument("--meta", type=Path, help="path to the encrypted meta (default: auto-locate; or TRACKSIDE_META)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("find", help="assets whose name contains PATTERN")
    p.add_argument("pattern")
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("cutin", help="assets whose name contains a cutin_file_id")
    p.add_argument("cutin_id")
    p.set_defaults(func=cmd_cutin)

    p = sub.add_parser("tables", help="list tables + the asset-index schema")
    p.set_defaults(func=cmd_tables)

    p = sub.add_parser("sql", help="run a read-only SELECT/PRAGMA against the decrypted meta")
    p.add_argument("query")
    p.set_defaults(func=cmd_sql)

    p = sub.add_parser("decrypt", help="write a plain (stdlib-readable) decrypted copy")
    p.add_argument("--out", default="meta_decrypted")
    p.set_defaults(func=cmd_decrypt)

    args = ap.parse_args()
    meta_path = args.meta or locate_meta(args.server)
    with Meta(args.server, meta_path) as m:
        args.func(m, args)


if __name__ == "__main__":
    main()
