#!/usr/bin/env python3
"""Sign and verify the restricted VOXO service manifest v1 envelope."""

import argparse
import base64
import datetime as dt
import json
import pathlib
import subprocess
import tempfile
import urllib.parse


SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamps must use UTC Z form")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_signed(signed, allow_expired=False):
    if not isinstance(signed, dict) or signed.get("schemaVersion") != 1:
        raise ValueError("unsupported schemaVersion")
    sequence = signed.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("sequence must be a positive integer")
    issued = utc(signed.get("issuedAt"))
    expires = utc(signed.get("expiresAt"))
    stale = utc(signed.get("staleUntil"))
    if not issued < expires < stale or stale - issued > dt.timedelta(days=30):
        raise ValueError("invalid manifest lifetime")
    if not allow_expired and expires <= dt.datetime.now(dt.timezone.utc):
        raise ValueError("manifest has expired")

    ingresses = signed.get("ingresses")
    if not isinstance(ingresses, list) or not 1 <= len(ingresses) <= 5:
        raise ValueError("invalid ingress count")
    ingress_ids = set()
    ingress_hosts = set()
    for ingress in ingresses:
        ingress_id = ingress.get("id")
        parsed = urllib.parse.urlsplit(ingress.get("baseUrl", ""))
        if not ingress_id or ingress_id in ingress_ids:
            raise ValueError("ingress ids must be unique")
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path not in ("", "/")
        ):
            raise ValueError("ingress must be an HTTPS origin")
        if (
            parsed.username
            or parsed.query
            or parsed.fragment
            or parsed.hostname in ingress_hosts
        ):
            raise ValueError("invalid or duplicate ingress host")
        ingress_ids.add(ingress_id)
        ingress_hosts.add(parsed.hostname)

    routing = signed.get("routing", {})
    if (
        routing.get("mode") != "weighted-session"
        or routing.get("failurePolicy") != "retry-next"
    ):
        raise ValueError("unsupported routing policy")
    targets = routing.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("routing targets are required")
    target_ids = set()
    total = 0
    for target in targets:
        ingress_id = target.get("ingressId")
        weight = target.get("weight")
        if ingress_id not in ingress_ids or ingress_id in target_ids:
            raise ValueError("invalid routing ingressId")
        if (
            not isinstance(weight, int)
            or isinstance(weight, bool)
            or not 0 <= weight <= 100
        ):
            raise ValueError("invalid routing weight")
        target_ids.add(ingress_id)
        total += weight
    if total != 100:
        raise ValueError("routing weights must total 100")

    routes = signed.get("routes", {})
    for name in ("tmdbApi", "tmdbImages", "backendApi", "legacyJackett"):
        route = routes.get(name)
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or ".." in route
        ):
            raise ValueError(f"invalid route {name}")
    if not routes["tmdbImages"].endswith("/"):
        raise ValueError("tmdbImages must end with slash")


def extract_public_key(private_key):
    der = subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    ).stdout
    if not der.startswith(SPKI_ED25519_PREFIX) or len(der) != len(
        SPKI_ED25519_PREFIX
    ) + 32:
        raise ValueError("private key is not Ed25519")
    return der[-32:]


def load_keys(path):
    keys = json.loads(path.read_text(encoding="utf-8")).get("keys")
    if not isinstance(keys, dict):
        raise ValueError("public key file must contain keys object")
    return keys


def sign(args):
    signed = json.loads(args.source.read_text(encoding="utf-8"))
    validate_signed(signed)
    public_key = b64url(extract_public_key(args.private_key))
    keys = load_keys(args.public_keys)
    if keys.get(args.key_id) != public_key:
        raise ValueError("private key does not match published keyId")
    with tempfile.NamedTemporaryFile() as payload, tempfile.NamedTemporaryFile() as sig:
        payload.write(canonical(signed))
        payload.flush()
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(args.private_key),
                "-in",
                payload.name,
                "-out",
                sig.name,
            ],
            check=True,
        )
        sig.seek(0)
        signature_value = b64url(sig.read())
    envelope = {
        "signed": signed,
        "signature": {
            "algorithm": "Ed25519",
            "keyId": args.key_id,
            "value": signature_value,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def verify(args):
    envelope = json.loads(args.manifest.read_text(encoding="utf-8"))
    signed = envelope.get("signed")
    if args.source is not None:
        source = json.loads(args.source.read_text(encoding="utf-8"))
        if source != signed:
            raise ValueError("signed payload does not match source")
    signature = envelope.get("signature", {})
    validate_signed(signed, allow_expired=args.allow_expired)
    if signature.get("algorithm") != "Ed25519":
        raise ValueError("unsupported signature algorithm")
    public_value = load_keys(args.public_keys).get(signature.get("keyId"))
    if public_value is None:
        raise ValueError("unknown keyId")
    public_der = SPKI_ED25519_PREFIX + b64url_decode(public_value)
    signature_bytes = b64url_decode(signature.get("value", ""))
    with (
        tempfile.NamedTemporaryFile() as payload,
        tempfile.NamedTemporaryFile() as public_key,
        tempfile.NamedTemporaryFile() as signature_file,
    ):
        payload.write(canonical(signed))
        payload.flush()
        public_key.write(public_der)
        public_key.flush()
        signature_file.write(signature_bytes)
        signature_file.flush()
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                public_key.name,
                "-rawin",
                "-in",
                payload.name,
                "-sigfile",
                signature_file.name,
            ],
            check=True,
            capture_output=True,
        )


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    signer = subparsers.add_parser("sign")
    signer.add_argument("--source", type=pathlib.Path, required=True)
    signer.add_argument("--private-key", type=pathlib.Path, required=True)
    signer.add_argument("--key-id", required=True)
    signer.add_argument("--public-keys", type=pathlib.Path, required=True)
    signer.add_argument("--output", type=pathlib.Path, required=True)
    signer.set_defaults(handler=sign)
    verifier = subparsers.add_parser("verify")
    verifier.add_argument("--manifest", type=pathlib.Path, required=True)
    verifier.add_argument("--public-keys", type=pathlib.Path, required=True)
    verifier.add_argument("--source", type=pathlib.Path)
    verifier.add_argument("--allow-expired", action="store_true")
    verifier.set_defaults(handler=verify)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
