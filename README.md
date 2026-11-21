# cyberbackup

Encrypted backup & cyber-recovery CLI written in Python. It zips a directory, encrypts it with AES-256-GCM, records the SHA-256 of the encrypted file in SQLite, and refuses to decrypt if the file has been modified (tampering / ransomware detection).

## Features
- AES-256-GCM encryption, key derived from a password with scrypt
- SHA-256 integrity record per backup stored in SQLite
- `recover` verifies the hash *before* decrypting; on mismatch it raises a **Tampering/Ransomware Detected** alert and blocks decryption (exit code 2)
- Backup files are made read-only; zip-slip protection on restore

## Install
```
pip install -r requirements.txt
```

## Usage
```
python3 cyberbackup.py backup ./mydir --out backups
python3 cyberbackup.py list
python3 cyberbackup.py verify backups/<file>.cbk
python3 cyberbackup.py recover backups/<file>.cbk --dest ./restored
```
Password is prompted, or read from the `BACKUP_PASSWORD` environment variable.

## Limitations
The hash database is stored locally, so an attacker able to modify both the backup and the database could defeat the check. Next steps: HMAC-sign the database or store it off-box / on write-once storage.
