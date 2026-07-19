#!/usr/bin/env python3
"""Generate aaReq token and merge into extensions JSON."""
import hashlib, json, base64, sys, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if len(sys.argv) != 5:
    print("Usage: gen_ext.py <key_hex> <epoch> <build_id> <query_hash>", file=sys.stderr)
    sys.exit(1)

key_hex, epoch, build_id, query_hash = sys.argv[1:5]
ts = (int(time.time() * 1000) // 300000) * 300000
payload = json.dumps({"v": 1, "ts": ts, "epoch": int(epoch), "buildId": build_id, "qh": query_hash}).encode()
iv = hashlib.sha256(f"{epoch}:{build_id}:{query_hash}:{ts}".encode()).digest()[:12]
aesgcm = AESGCM(bytes.fromhex(key_hex))
token = b"\x01" + iv + aesgcm.encrypt(iv, payload, None)
aa_req = base64.b64encode(token).decode()

ext = {"persistedQuery": {"version": 1, "sha256Hash": query_hash}, "aaReq": aa_req}
print(json.dumps(ext, separators=(",", ":")))
