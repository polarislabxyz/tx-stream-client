#!/usr/bin/env python3
"""Check every exported file against its immutable contract manifest."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "fixtures/manifest.json").read_text())
assert manifest["schema_version"] == 1
assert len(manifest["source_commit"]) == 40
for name, expected in manifest["files"].items():
    path = (root / name).resolve()
    assert path.is_relative_to(root), f"unsafe manifest path: {name}"
    data = path.read_bytes()
    assert len(data) == expected["size"], f"size mismatch: {name}"
    assert hashlib.sha256(data).hexdigest() == expected["sha256"], f"hash mismatch: {name}"
print(f"Verified {len(manifest['files'])} files from {manifest['source_commit']}")
