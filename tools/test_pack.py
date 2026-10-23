# SPDX-License-Identifier: GPL-2.0-only
"""Host test: pack a module from mock assets and check the ZIP layout."""
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as directory:
        d = Path(directory)
        (d / "susfs_insmod").write_bytes(b"")
        kmis = ["android12-5.10", "android15-6.6", "android17-6.18"]
        for k in kmis:
            (d / f"susfs_guard_lkm-{k}.ko").write_bytes(b"mock")
        out = d / "m.zip"
        ddk_images = d / "ddk-images.json"
        ddk_images.write_text('["ghcr.io/ylarod/ddk-min:android13-5.15-20260828@sha256:'
                              + "0" * 64 + '"]\n')
        subprocess.run([sys.executable, str(ROOT / "tools/pack_module.py"),
                        "--ko-dir", str(d), "--insmod", str(d / "susfs_insmod"),
                        "--tag", "v0.0.0-test", "--sha", "1" * 40, "--run-id", "12345",
                        "--ddk-images", str(ddk_images), "--out", str(out)], check=True)
        with zipfile.ZipFile(out) as z:
            names = set(z.namelist())
            need = {"post-fs-data.sh", "customize.sh", "kmi.sh", "early-dispatch.sh", "load.sh", "uninstall.sh", "kmis", "module.prop",
                    "bin/susfs_insmod", "provenance.json", "LICENSE"} | {f"lib/susfs_guard_lkm-{k}.ko" for k in kmis}
            assert not need - names, f"missing: {need - names}"
            prop = z.read("module.prop").decode()
            assert "id=susfs_guard_lkm" in prop and "version=v0.0.0-test" in prop, prop
            assert z.read("kmis").decode().split() == kmis
            assert "early_load" not in names
            provenance = z.read("provenance.json").decode()
            for needle in ('"github_sha": "' + "1" * 40 + '"',
                           '"github_run_id": 12345',
                           '"build_workflow": ".github/workflows/build-ddk.yml"',
                           "sha256:" + "0" * 64):
                assert needle in provenance, (needle, provenance)
        print("pack test ok")


if __name__ == "__main__":
    main()
