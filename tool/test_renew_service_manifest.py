import copy
import datetime as dt
import json
import pathlib
import unittest
import tempfile
import subprocess
from types import SimpleNamespace
import service_manifest
from renew_service_manifest import renew
from renew_service_manifest import renewed, MUTABLE


class RenewalTest(unittest.TestCase):
    def setUp(self):
        self.source = json.loads((pathlib.Path(__file__).resolve().parents[1] /
                                  'manifest/service-manifest-source.json').read_text())
        self.expiry = dt.datetime.fromisoformat(self.source['expiresAt'].replace('Z', '+00:00'))

    def test_fresh_is_unchanged(self):
        self.assertIsNone(renewed(self.source, self.expiry - dt.timedelta(days=4)))

    def test_due_and_expired_preserve_routes(self):
        for now in [self.expiry - dt.timedelta(days=3), self.expiry + dt.timedelta(days=20)]:
            before = copy.deepcopy(self.source)
            result = renewed(self.source, now)
            self.assertEqual(self.source, before)
            self.assertEqual(result['sequence'], before['sequence'] + 1)
            self.assertEqual({k: v for k, v in result.items() if k not in MUTABLE},
                             {k: v for k, v in before.items() if k not in MUTABLE})
            self.assertEqual(result['expiresAt'], (now + dt.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            self.assertEqual(result['staleUntil'], (now + dt.timedelta(days=29)).strftime('%Y-%m-%dT%H:%M:%SZ'))


class SigningTest(unittest.TestCase):
    def test_renewal_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'manifest').mkdir()
            (root / 'public').mkdir()
            key = root / 'test-key.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(key)], check=True, capture_output=True)
            keys = root / 'public/service-manifest-public-keys.json'
            keys.write_text(json.dumps({'keys': {'test': service_manifest.b64url(service_manifest.extract_public_key(key))}}))
            source = root / 'manifest/service-manifest-source.json'
            envelope = root / 'public/service-manifest.json'
            data = json.loads((pathlib.Path(__file__).resolve().parents[1] / 'manifest/service-manifest-source.json').read_text())
            now = dt.datetime.now(dt.timezone.utc)
            for field, days in [('issuedAt', -1), ('expiresAt', 1), ('staleUntil', 20)]:
                data[field] = (now + dt.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
            source.write_text(json.dumps(data))
            service_manifest.sign(SimpleNamespace(source=source, output=envelope, private_key=key, public_keys=keys, key_id='test'))
            renew(root, key)
            self.assertEqual(json.loads(source.read_text())['sequence'], data['sequence'] + 1)
            service_manifest.verify(SimpleNamespace(source=source, manifest=envelope, public_keys=keys, allow_expired=False))
            before = (source.read_bytes(), envelope.read_bytes())
            renew(root, key)
            self.assertEqual(before, (source.read_bytes(), envelope.read_bytes()))
            changed = json.loads(source.read_text())
            changed['sequence'] += 1
            source.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                renew(root, key)
            self.assertEqual(before[1], envelope.read_bytes())


if __name__ == '__main__':
    unittest.main()
