#!/usr/bin/env python3
"""cyberbackup - encrypted backup & cyber-recovery CLI.

backup  : zip a directory -> encrypt with AES-256-GCM -> store SHA-256 of the
          encrypted file in a SQLite database.
recover : re-hash the backup file and compare with the database BEFORE
          decrypting. On mismatch, raise a Tampering/Ransomware alert and
          refuse to decrypt.
list    : show recorded backups.
verify  : integrity check only (no decryption).

Requires: pip install cryptography
"""
import argparse
import getpass
import hashlib
import io
import os
import sqlite3
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CBK1"
SALT_LEN, NONCE_LEN = 16, 12
DEFAULT_BACKUP_DIR = Path("backups")
DEFAULT_DB = Path("backups/backups.db")

EXIT_OK, EXIT_ERROR, EXIT_TAMPER = 0, 1, 2


def get_password(confirm=False):
    pw = os.environ.get("BACKUP_PASSWORD")
    if pw:
        return pw
    pw = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Confirm password: ") != pw:
        sys.exit("Passwords do not match.")
    if not pw:
        sys.exit("Empty password not allowed.")
    return pw


def derive_key(password, salt):
    # scrypt -> 32 bytes = AES-256 key
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def open_db(db_path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.execute(
        """CREATE TABLE IF NOT EXISTS backups (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               filename TEXT NOT NULL UNIQUE,
               source TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               size INTEGER NOT NULL,
               created_utc TEXT NOT NULL)"""
    )
    return con


def zip_directory(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src.rglob("*")):
            if p.is_file() and not p.is_symlink():
                zf.write(p, p.relative_to(src))
    return buf.getvalue()


def safe_extract(data, dest):
    dest = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for m in zf.namelist():  # block zip-slip
            if not (dest / m).resolve().is_relative_to(dest):
                raise ValueError(f"Unsafe path in archive: {m}")
        zf.extractall(dest)


def cmd_backup(a):
    src = Path(a.directory)
    if not src.is_dir():
        print(f"error: {src} is not a directory", file=sys.stderr)
        return EXIT_ERROR
    password = get_password(confirm=not os.environ.get("BACKUP_PASSWORD"))
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    header = MAGIC + salt + nonce
    # header is bound as associated data so it can't be altered undetected
    ct = AESGCM(derive_key(password, salt)).encrypt(nonce, zip_directory(src), header)

    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = out_dir / f"{src.resolve().name}_{stamp}.cbk"
    out.write_bytes(header + ct)
    os.chmod(out, 0o400)  # read-only: light immutability

    digest = sha256_file(out)
    with open_db(Path(a.db)) as con:
        con.execute(
            "INSERT INTO backups (filename, source, sha256, size, created_utc) VALUES (?,?,?,?,?)",
            (out.name, str(src.resolve()), digest, out.stat().st_size, stamp),
        )
    print(f"Backup created: {out}\nSHA-256: {digest}")
    return EXIT_OK


def check_integrity(backup, db):
    """Returns (ok, message)."""
    with open_db(db) as con:
        row = con.execute("SELECT sha256 FROM backups WHERE filename=?", (backup.name,)).fetchone()
    if row is None:
        return False, f"No integrity record for {backup.name} in database."
    current = sha256_file(backup)
    if current != row[0]:
        return False, (
            "*** ALERT: TAMPERING / RANSOMWARE DETECTED ***\n"
            f"  expected SHA-256: {row[0]}\n  actual SHA-256:   {current}"
        )
    return True, f"Integrity OK (SHA-256 {current})"


def cmd_verify(a):
    backup = Path(a.backup)
    if not backup.is_file():
        print(f"error: {backup} not found", file=sys.stderr)
        return EXIT_ERROR
    ok, msg = check_integrity(backup, Path(a.db))
    print(msg, file=sys.stdout if ok else sys.stderr)
    return EXIT_OK if ok else EXIT_TAMPER


def cmd_recover(a):
    backup = Path(a.backup)
    if not backup.is_file():
        print(f"error: {backup} not found", file=sys.stderr)
        return EXIT_ERROR
    ok, msg = check_integrity(backup, Path(a.db))
    if not ok:
        print(msg, file=sys.stderr)
        print("Decryption BLOCKED.", file=sys.stderr)
        return EXIT_TAMPER
    print(msg)

    blob = backup.read_bytes()
    header, ct = blob[: 4 + SALT_LEN + NONCE_LEN], blob[4 + SALT_LEN + NONCE_LEN :]
    if header[:4] != MAGIC:
        print("error: not a cyberbackup file", file=sys.stderr)
        return EXIT_ERROR
    salt, nonce = header[4 : 4 + SALT_LEN], header[4 + SALT_LEN :]
    try:
        data = AESGCM(derive_key(get_password(), salt)).decrypt(nonce, ct, header)
    except InvalidTag:
        print("error: wrong password or corrupted data", file=sys.stderr)
        return EXIT_ERROR
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    safe_extract(data, dest)
    print(f"Recovered to {dest}")
    return EXIT_OK


def cmd_list(a):
    with open_db(Path(a.db)) as con:
        rows = con.execute("SELECT filename, source, size, created_utc, sha256 FROM backups").fetchall()
    for r in rows:
        print(f"{r[0]}  src={r[1]}  {r[2]}B  {r[3]}  sha256={r[4][:12]}...")
    if not rows:
        print("No backups recorded.")
    return EXIT_OK


def main():
    p = argparse.ArgumentParser(description="Encrypted backup & cyber recovery tool")
    p.add_argument("--db", default=str(DEFAULT_DB), help="SQLite integrity database")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("backup", help="zip + encrypt a directory")
    b.add_argument("directory")
    b.add_argument("--out", default=str(DEFAULT_BACKUP_DIR))
    b.set_defaults(fn=cmd_backup)

    r = sub.add_parser("recover", help="verify integrity, then decrypt")
    r.add_argument("backup")
    r.add_argument("--dest", required=True)
    r.set_defaults(fn=cmd_recover)

    v = sub.add_parser("verify", help="integrity check only")
    v.add_argument("backup")
    v.set_defaults(fn=cmd_verify)

    l = sub.add_parser("list", help="list recorded backups")
    l.set_defaults(fn=cmd_list)

    a = p.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
