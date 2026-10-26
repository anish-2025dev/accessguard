"""``accessguard-verifier keygen``: a new X25519 key pair for the credential vault (ADR 015).

The private key goes only into the verifier process's secret store
(``ACCESSGUARD_VERIFIER_PRIVATE_KEY``); the public key goes to the API
(``ACCESSGUARD_VERIFIER_PUBLIC_KEY``)."""

from __future__ import annotations

import argparse

from accessguard_verifier.vault import new_keypair


def main() -> int:
    ap = argparse.ArgumentParser(prog="accessguard-verifier")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", help="print a new vault key pair as environment variables")
    ap.parse_args()
    private, public = new_keypair()
    print(f"ACCESSGUARD_VERIFIER_PRIVATE_KEY={private}  # verifier worker only")
    print(f"ACCESSGUARD_VERIFIER_PUBLIC_KEY={public}  # api")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
