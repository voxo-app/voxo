#!/usr/bin/env python3
"""Renew only the lifetime of an authenticated service manifest."""
import argparse
import copy
import datetime as dt
import json
import pathlib
import tempfile
from types import SimpleNamespace

import service_manifest as manifest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MUTABLE = {'sequence', 'issuedAt', 'expiresAt', 'staleUntil'}


def renewed(source, now, force=False):
    if not force and manifest.utc(source['expiresAt']) - now > dt.timedelta(days=3):
        return None
    result = copy.deepcopy(source)
    result['sequence'] += 1
    for name, days in [('issuedAt', 0), ('expiresAt', 7), ('staleUntil', 29)]:
        result[name] = (now + dt.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    assert {k: v for k, v in result.items() if k not in MUTABLE} == {
        k: v for k, v in source.items() if k not in MUTABLE}
    return result


def renew(root, private_key, force=False):
    source = root / 'manifest/service-manifest-source.json'
    envelope = root / 'public/service-manifest.json'
    keys = root / 'public/service-manifest-public-keys.json'
    manifest.verify(SimpleNamespace(source=source, manifest=envelope,
                                    public_keys=keys, allow_expired=True))
    current = json.loads(source.read_text())
    candidate = renewed(current, dt.datetime.now(dt.timezone.utc), force=force)
    if candidate is None:
        print('Manifest is fresh; no changes')
        return
    key_id = json.loads(envelope.read_text())['signature']['keyId']
    with tempfile.TemporaryDirectory() as directory:
        candidate_source = pathlib.Path(directory) / 'source.json'
        candidate_envelope = pathlib.Path(directory) / 'envelope.json'
        candidate_source.write_text(json.dumps(candidate, ensure_ascii=False, indent=2) + '\n')
        manifest.sign(SimpleNamespace(source=candidate_source, private_key=private_key,
                                      key_id=key_id, public_keys=keys, output=candidate_envelope))
        manifest.verify(SimpleNamespace(source=candidate_source, manifest=candidate_envelope,
                                        public_keys=keys, allow_expired=False))
        source.write_bytes(candidate_source.read_bytes())
        envelope.write_bytes(candidate_envelope.read_bytes())
    print(f"Renewed sequence {candidate['sequence']}; expires {candidate['expiresAt']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--private-key', type=pathlib.Path, required=True)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    renew(ROOT, args.private_key, force=args.force)
