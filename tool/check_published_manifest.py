#!/usr/bin/env python3
"""Verify anonymous distribution, including signature and expected sequence."""
import pathlib
import tempfile
import time
import urllib.request
from types import SimpleNamespace
import service_manifest as manifest

root = pathlib.Path(__file__).resolve().parents[1]
for attempt in range(6):
    try:
        url = 'https://raw.githubusercontent.com/voxo-app/voxo/main/public/service-manifest.json'
        with urllib.request.urlopen(url, timeout=20) as response:
            assert response.status == 200
            content = response.read(1024 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            downloaded = pathlib.Path(directory) / 'manifest.json'
            downloaded.write_bytes(content)
            manifest.verify(SimpleNamespace(manifest=downloaded,
                source=root / 'manifest/service-manifest-source.json',
                public_keys=root / 'public/service-manifest-public-keys.json', allow_expired=False))
        print('Anonymous HTTP 200; expected payload and signature verified')
        break
    except Exception:
        if attempt == 5:
            raise SystemExit('Published manifest verification failed')
        time.sleep(15)
