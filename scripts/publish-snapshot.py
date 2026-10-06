#!/usr/bin/env python3
"""Publish a complete assembled snapshot after verifying every uploaded asset."""
import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from snapshotlib import manifest_snapshot_digest


def api(url, token, method="GET", data=None, content_type="application/vnd.github+json",
        accept="application/vnd.github+json"):
    headers = {"Accept": accept, "Authorization": f"Bearer {token}",
               "X-GitHub-Api-Version": "2022-11-28"}
    if data is not None:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.status, response.read()


def verify_snapshot(folder):
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("snapshot directory is missing or unsafe")
    manifest_path, sums_path = folder / "manifest.json", folder / "SHA256SUMS"
    if manifest_path.is_symlink() or sums_path.is_symlink():
        raise ValueError("snapshot metadata must be regular files")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != 2:
        raise ValueError("unsupported snapshot manifest schema")
    sums = {}
    for line in sums_path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match.group(2) in sums:
            raise ValueError("malformed or duplicate SHA256SUMS row")
        digest, name = match.groups()
        path = folder / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"snapshot checksum failed: {name}")
        sums[name] = digest
    asset_names = {path.name for path in folder.iterdir() if path.is_file()}
    covered = asset_names - {"SHA256SUMS"}
    if set(sums) != covered:
        raise ValueError("SHA256SUMS does not cover the complete snapshot asset set")
    if manifest.get("snapshot") not in (folder.name.rsplit("-", 1)[-1],):
        raise ValueError("snapshot directory name does not match manifest digest")
    matrix_path = folder / "kernel-matrix.json"
    if (matrix_path.is_symlink() or not matrix_path.is_file() or
            hashlib.sha256(matrix_path.read_bytes()).hexdigest() != manifest.get("matrix_sha256")):
        raise ValueError("snapshot matrix bytes do not match manifest provenance")
    for key, build in manifest.get("builds", {}).items():
        for kind, module in build.get("modules", {}).items():
            name = module.get("asset_file")
            if (not isinstance(name, str) or sums.get(name) != module.get("sha256") or
                    name not in asset_names):
                raise ValueError(f"snapshot build {key}/{kind} has an unchecksummed module asset")
    if manifest_snapshot_digest(manifest) != manifest.get("snapshot"):
        raise ValueError("snapshot digest does not match matrix, build provenance, and module identities")
    for release_models in manifest.get("releases", {}).values():
        for item in release_models.values():
            if item.get("status") == "unsupported":
                if not item.get("reason"):
                    raise ValueError("unsupported mapping lacks reason")
                continue
            if item.get("status") != "experimental" or not item.get("build_key"):
                raise ValueError("release contains invalid or unverified model status")
            for module in item.get("modules", {}).values():
                name = module.get("file", "")
                if (not re.fullmatch(r"(?:iptable|ip6table)_keenpbr-[0-9a-f]{64}\.ko", name)
                        or sums.get(name) != module.get("sha256")):
                    raise ValueError("release mapping does not point to a checksummed content-addressed module")
    if len(asset_names) > 1000:
        raise ValueError("snapshot exceeds GitHub's 1000 asset limit")
    return manifest, asset_names


def remote_assets(token, release):
    assets = {}
    page = 1
    while True:
        separator = "&" if "?" in release["assets_url"] else "?"
        _, raw = api(f"{release['assets_url']}{separator}per_page=100&page={page}", token)
        items = json.loads(raw)
        if not isinstance(items, list):
            raise ValueError("GitHub returned a malformed release asset page")
        assets.update((item["name"], item) for item in items)
        if len(items) < 100:
            return assets
        page += 1


def verify_remote_assets(token, release, folder, asset_names):
    assets = remote_assets(token, release)
    if set(assets) != asset_names:
        raise ValueError("GitHub asset coverage differs from the validated snapshot")
    for name in sorted(asset_names):
        expected = hashlib.sha256((folder / name).read_bytes()).hexdigest()
        advertised = assets[name].get("digest")
        if advertised:
            if advertised != "sha256:" + expected:
                raise ValueError(f"uploaded asset digest mismatch: {name}")
        else:
            _, raw = api(assets[name]["url"], token, accept="application/octet-stream")
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError(f"downloaded uploaded asset digest mismatch: {name}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--notes", type=Path, required=True)
    parser.add_argument("--repository", required=True, help="GitHub owner/repository")
    parser.add_argument("--target-commit", required=True)
    parser.add_argument("--token", default="")
    args = parser.parse_args()
    release_id = None
    created_draft = False
    api_root = f"https://api.github.com/repos/{args.repository}"
    try:
        if not args.token:
            raise ValueError("GITHUB_TOKEN is required")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
            raise ValueError("--repository must be an owner/repository name")
        if not re.fullmatch(r"[0-9a-f]{40}", args.target_commit):
            raise ValueError("--target-commit must be an exact Git commit SHA")
        manifest, asset_names = verify_snapshot(args.snapshot)
        if args.notes.is_symlink() or not args.notes.is_file():
            raise ValueError("release notes are missing or unsafe")
        body = args.notes.read_text()
        if len(body.encode()) > 100_000:
            raise ValueError("release description remains above the configured size limit")
        digest = manifest["snapshot"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid snapshot digest")
        tag = f"modules-v{manifest['version']}-{digest}"
        try:
            _, raw = api(api_root + "/releases/tags/" + urllib.parse.quote(tag, safe=""), args.token)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
        else:
            existing = json.loads(raw)
            release_id = existing["id"]
            if existing.get("draft"):
                existing_assets = set(remote_assets(args.token, existing))
                if existing_assets - asset_names:
                    raise ValueError(f"snapshot tag {tag} has unexpected assets")
                release = existing
            else:
                verify_remote_assets(args.token, existing, args.snapshot, asset_names)
                print(f"Snapshot {tag} already exists with identical published assets")
                return 0
        if release_id is None:
            _, raw = api(api_root + "/releases", args.token, "POST", json.dumps({
                "tag_name": tag, "target_commitish": args.target_commit, "name": tag,
                "body": body, "draft": True, "prerelease": False}).encode())
            release = json.loads(raw)
            release_id = release["id"]
            created_draft = True
        if release.get("draft"):
            upload_url = release["upload_url"].split("{", 1)[0]
            present = set(remote_assets(args.token, release))
            for name in sorted(asset_names - present):
                encoded = urllib.parse.urlencode({"name": name})
                api(upload_url + "?" + encoded, args.token, "POST", (args.snapshot / name).read_bytes(),
                    "application/octet-stream")
        _, raw = api(api_root + f"/releases/{release_id}", args.token)
        uploaded = json.loads(raw)
        if not uploaded.get("draft"):
            raise ValueError("new snapshot release unexpectedly is not a draft")
        verify_remote_assets(args.token, uploaded, args.snapshot, asset_names)
        _, raw = api(api_root + f"/releases/{release_id}", args.token, "PATCH",
                     json.dumps({"draft": False}).encode())
        published = json.loads(raw)
        if published.get("draft"):
            raise ValueError("GitHub release did not publish with complete validated asset coverage")
        verify_remote_assets(args.token, published, args.snapshot, asset_names)
        print(f"Published verified snapshot {tag} ({len(asset_names)} assets)")
    except (OSError, ValueError, KeyError, urllib.error.URLError, json.JSONDecodeError) as exc:
        if created_draft and release_id is not None and args.token:
            try:
                _, raw = api(api_root + f"/releases/{release_id}", args.token)
                if json.loads(raw).get("draft"):
                    api(api_root + f"/releases/{release_id}", args.token, "DELETE")
            except Exception:
                pass
        print(f"snapshot publication failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
