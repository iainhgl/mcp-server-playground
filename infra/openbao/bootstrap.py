# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Initialise, unseal and configure OpenBao. Safe to run on every `up`.

- First run: init with a single unseal key and save it plus the root token to
  SECRETS_FILE (./.secrets, gitignored). In AWS the equivalent is KMS, which
  needs no unsealing; this step is a local-only concern.
- Every run: unseal if sealed, then make sure these exist:
    transit/  + key `vault-dek`   (≈ KMS key used for envelope encryption)
    secret/   KV v2               (≈ Secrets Manager)
"""

import json
import os
import sys
import time
from pathlib import Path

import httpx

BAO = os.environ.get("BAO_ADDR", "http://openbao:8200")
SECRETS_FILE = Path(os.environ.get("SECRETS_FILE", "/secrets/openbao-init.json"))


def log(msg: str) -> None:
    print(f"[openbao-init] {msg}", flush=True)


def main() -> None:
    c = httpx.Client(base_url=f"{BAO}/v1", timeout=10)

    for _ in range(60):
        try:
            c.get("/sys/health")
            break
        except httpx.TransportError:
            time.sleep(1)
    else:
        sys.exit("OpenBao not reachable")

    if not c.get("/sys/init").json()["initialized"]:
        r = c.put("/sys/init", json={"secret_shares": 1, "secret_threshold": 1})
        r.raise_for_status()
        SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SECRETS_FILE.write_text(json.dumps(r.json(), indent=2))
        SECRETS_FILE.chmod(0o600)
        log(f"initialised; unseal key + root token written to {SECRETS_FILE}")
    elif not SECRETS_FILE.exists():
        sys.exit(f"OpenBao is initialised but {SECRETS_FILE} is missing: run `make nuke` to reset")

    init = json.loads(SECRETS_FILE.read_text())

    if c.get("/sys/seal-status").json()["sealed"]:
        c.put("/sys/unseal", json={"key": init["keys_base64"][0]}).raise_for_status()
        log("unsealed")

    # After unseal, Raft has to elect this node leader before storage is writable.
    # /sys/health returns 200 only on an active, unsealed node.
    for _ in range(60):
        if c.get("/sys/health").status_code == 200:
            break
        time.sleep(1)
    else:
        sys.exit("OpenBao did not become active")

    c.headers["X-Vault-Token"] = init["root_token"]

    mounts = c.get("/sys/mounts").json()
    mounts = mounts.get("data", mounts)
    if "transit/" not in mounts:
        c.post("/sys/mounts/transit", json={"type": "transit"}).raise_for_status()
        log("enabled transit/")
    if "secret/" not in mounts:
        c.post("/sys/mounts/secret", json={"type": "kv", "options": {"version": "2"}}).raise_for_status()
        log("enabled secret/ (kv v2)")

    if c.get("/transit/keys/vault-dek").status_code == 404:
        c.post("/transit/keys/vault-dek", json={"type": "aes256-gcm96"}).raise_for_status()
        log("created transit key vault-dek")

    log("ready")


if __name__ == "__main__":
    main()
