"""Shared deterministic SDK matrix and descriptor identity helpers."""
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_RE = re.compile(r"^KN-[0-9]{4}$")
CONFIG_RE = re.compile(r"^CONFIG_([A-Z0-9_]+)=(.*)$")
ASSIGN_RE = re.compile(r"^\s*([A-Z0-9_]+)\s*:?=\s*([^#\s]+)")
KERNEL_RE = re.compile(r"^\s*KERNEL_49_SOURCE_VERSION\s*:?=\s*([^#\s]+)", re.M)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_key(configuration, build_inputs_sha256, source_sha256, version, contract, environment):
    """Hash module inputs, excluding SDK tag/ref provenance used only for lookup."""
    sdk_input_key = configuration.get("sdk_input_key")
    if not re.fullmatch(r"[0-9a-f]{64}", sdk_input_key or ""):
        raise ValueError("configuration must include a SHA256 sdk_input_key")
    return canonical_hash({"schema_version": 1, "sdk_input_key": sdk_input_key,
                          "build_inputs_sha256": build_inputs_sha256,
                          "source_sha256": source_sha256, "version": version,
                          "contract": contract, "environment": environment})


def build_inputs_sha256(root=ROOT):
    root = Path(root)
    names = ("scripts/build.sh", "scripts/prepare-sdk.sh", "scripts/sdk_matrix.py",
             "scripts/kmodlib.py", "scripts/model_tools.py", "package/Makefile", "sdk.lock",
             ".ci/build-environment.json", ".ci/setup-build-env.sh", ".ci/cmake-3.8.1-limits.patch",
             ".ci/m4-1.4.18-sigstksz.patch")
    digest = hashlib.sha256()
    for name in names:
        path = root / name
        digest.update(name.encode() + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_build_host(environment):
    """Reject descriptor builds outside the pinned architecture and toolchain."""
    build = environment.get("build", {})
    if environment.get("platform") != "linux/amd64" or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("descriptor builds require the pinned linux/amd64 host")
    release = Path("/etc/os-release").read_text()
    if not re.search(r"^ID=debian$", release, re.M) or not re.search(r"^VERSION_CODENAME=bookworm$", release, re.M):
        raise ValueError("descriptor builds require Debian bookworm")
    if platform.python_version() != "3.14.2":
        raise ValueError("descriptor builds require Python 3.14.2")
    for field in ("host_cc", "host_cxx"):
        compiler = build.get(field)
        version = subprocess.check_output([compiler, "-dumpfullversion"], text=True).strip()
        if not version.startswith("12."):
            raise ValueError(f"descriptor builds require GCC 12: {compiler} reports {version}")


def verify_kernel_providers(config_text, symvers_text, kernel_source):
    """Validate provider exports from Module.symvers for modules or source for built-ins."""
    kernel_source = Path(kernel_source)
    symvers = {line.split()[1] for line in symvers_text.splitlines() if len(line.split()) >= 2}
    result = {}
    providers = {
        "ipv4": ("CONFIG_IP_NF_IPTABLES", "net/ipv4/netfilter/ip_tables.c",
                 ("ipt_do_table", "ipt_alloc_initial_table", "ipt_register_table", "ipt_unregister_table")),
        "ipv6": ("CONFIG_IP6_NF_IPTABLES", "net/ipv6/netfilter/ip6_tables.c",
                 ("ip6t_do_table", "ip6t_alloc_initial_table", "ip6t_register_table", "ip6t_unregister_table")),
    }
    config = dict(re.findall(r"^CONFIG_([A-Z0-9_]+)=(y|m)$", config_text, re.M))
    for family, (option, source, symbols) in providers.items():
        mode = config.get(option.removeprefix("CONFIG_"))
        if mode is None:
            if family == "ipv4":
                raise ValueError("IPv4 iptables provider is disabled in effective kernel config")
            result[family] = {"supported": False, "config": "disabled", "symbols": []}
            continue
        if mode == "m":
            missing = set(symbols) - symvers
            if missing:
                raise ValueError(f"{family} provider Module.symvers missing exports: {', '.join(sorted(missing))}")
            evidence = "Module.symvers"
        else:
            source_path = kernel_source / source
            if not source_path.is_file():
                raise ValueError(f"pinned kernel source lacks built-in {family} provider file: {source}")
            source_text = source_path.read_text(errors="replace")
            missing = [symbol for symbol in symbols
                       if not re.search(r"EXPORT_SYMBOL(?:_GPL)?\s*\(\s*" + re.escape(symbol) + r"\s*\)", source_text)]
            if missing:
                raise ValueError(f"built-in {family} provider lacks source exports: {', '.join(missing)}")
            evidence = "pinned-kernel-source-export-declarations"
        result[family] = {"supported": True, "config": mode, "evidence": evidence, "symbols": list(symbols)}
    return result


def git(git_path, *args):
    path = Path(git_path)
    command = ["git", "-C", str(path)] if (path / ".git").exists() else ["git", "--git-dir", str(path)]
    return subprocess.check_output([*command, *args], text=True, stderr=subprocess.STDOUT).strip()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _show(repo, ref, path):
    repo_path = Path(repo)
    command = ["git", "-C", str(repo_path)] if (repo_path / ".git").exists() else ["git", "--git-dir", str(repo_path)]
    return subprocess.check_output([*command, "show", f"{ref}:{path}"], stderr=subprocess.STDOUT)


def _source_version(repo, commit):
    text = _show(repo, commit, "include/kernel-defaults.mk").decode()
    match = KERNEL_RE.search(text)
    if not match:
        raise ValueError("include/kernel-defaults.mk has no literal KERNEL_49_SOURCE_VERSION")
    return match.group(1).strip('"\'')


def _kernel_ref(kernel_git, version):
    tag = version
    # --git-dir works for bare repositories and normal repositories alike.
    try:
        return git(kernel_git, "rev-parse", f"refs/tags/{tag}^{{commit}}"), tag
    except subprocess.CalledProcessError:
        # An explicit remote may not be cloned; resolve its immutable tag without mutating it.
        rows = subprocess.check_output(["git", "ls-remote", kernel_git,
                                        f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"], text=True).splitlines()
        for row in rows:
            ref, name = row.split("\t", 1)
            if name == f"refs/tags/{tag}^{{}}":
                return ref, tag
        for row in rows:
            ref, name = row.split("\t", 1)
            if name == f"refs/tags/{tag}":
                return ref, tag
    raise ValueError(f"kernel source tag {tag!r} not found in {kernel_git}")


def _kernel_tag_refs(kernel_git, versions):
    path = Path(kernel_git)
    if path.exists():
        return {version: _kernel_ref(kernel_git, version)[0] for version in versions}
    rows = subprocess.check_output(["git", "ls-remote", kernel_git], text=True).splitlines()
    refs = {}
    for row in rows:
        oid, name = row.split("\t", 1)
        if not name.startswith("refs/tags/"):
            continue
        tag = name[len("refs/tags/"):]
        if tag.endswith("^{}"):
            refs[tag[:-3]] = oid
        else:
            refs.setdefault(tag, oid)
    return {version: refs[version] for version in versions if version in refs}


def _tree(repo, commit):
    rows = git(repo, "ls-tree", "-r", "--full-tree", "-z", commit).split("\0")
    files = {}
    for row in rows:
        if not row:
            continue
        meta, name = row.split("\t", 1)
        mode, kind, oid = meta.split()
        if kind == "blob":
            files[name] = (oid, mode)
    return files


def _read_blob(repo, oid):
    repo_path = Path(repo)
    command = ["git", "-C", str(repo_path)] if (repo_path / ".git").exists() else ["git", "--git-dir", str(repo_path)]
    return subprocess.check_output([*command, "cat-file", "blob", oid])


def _tracked_tree_identity(files):
    # Root README is the only proven docs-only exclusion; all other tracked inputs count.
    digest = hashlib.sha256()
    for path, (oid, mode) in sorted(files.items()):
        if path == "README.md":
            continue
        digest.update(path.encode() + b"\0" + mode.encode() + b"\0" + oid.encode() + b"\n")
    return digest.hexdigest()


def _parse_config(content, path):
    values = {}
    for line in content.decode().splitlines():
        if line.startswith("#"):
            continue
        match = CONFIG_RE.match(line)
        if not match:
            continue
        key, value = match.groups()
        if key in values:
            raise ValueError(f"duplicate CONFIG_{key} in {path}")
        if value.startswith('"'):
            value = json.loads(value)
        values[key] = value
    return values


def _board_fields(content, path):
    fields = {}
    for line in content.decode().splitlines():
        match = ASSIGN_RE.match(line)
        if match and match.group(1) in {"ARCH", "KERNEL_PATCHVER"}:
            key, value = match.groups()
            if "$" in value or key in fields:
                raise ValueError(f"dynamic or duplicate {key} in {path}")
            fields[key] = value
    if set(fields) != {"ARCH", "KERNEL_PATCHVER"}:
        raise ValueError(f"{path} must declare ARCH and KERNEL_PATCHVER")
    return fields


def _model_entry(repo, commit, files, path, kernel_ref):
    parts = path.split("/")
    if len(parts) != 5 or parts[:2] != ["target", "linux"] or parts[-1] != "ndwrt.config":
        raise ValueError(f"unsupported model config path: {path}")
    board, model = parts[2:4]
    if not MODEL_RE.fullmatch(model):
        raise ValueError(f"model directory is not an exact KN ID: {path}")
    board_path = f"target/linux/{board}/Makefile"
    if path not in files or board_path not in files:
        raise ValueError(f"tracked model config or board Makefile missing: {path}")
    if files[path][1] not in {"100644", "100755"} or files[board_path][1] not in {"100644", "100755"}:
        raise ValueError(f"model config and board Makefile must be regular tracked files: {path}")
    config = _read_blob(repo, files[path][0])
    board_data = _read_blob(repo, files[board_path][0])
    fields = _board_fields(board_data, board_path)
    values = _parse_config(config, path)
    arch, patchver = fields["ARCH"], fields["KERNEL_PATCHVER"]
    if arch not in {"mips", "mipsel", "aarch64"} or patchver != "4.9":
        raise ValueError(f"unsupported SDK target {board}: {arch}/{patchver}")
    if (values.get("TARGET_BOARD"), values.get("ARCH"), values.get("TARGET_ARCH_PACKAGES")) != (board, arch, model):
        raise ValueError(f"board/model/architecture config mismatch: {path}")
    info = {"kernel_ref": kernel_ref, "kernel_source_version": None,
            "kernel_patchver": patchver, "model": model, "board": board,
            "arch": arch, "config": path, "config_sha256": sha256(config),
            "board_makefile_sha256": sha256(board_data),
            "sdk_build_tree_sha256": _tracked_tree_identity(files),
            "input_scope": "all tracked SDK files except root README.md"}
    key = canonical_hash(info)
    return model, key, info


def generate_matrix(sdk, kernel_git, repository, kernel_repository=None):
    tags = git(sdk, "tag", "--list").splitlines()
    if not tags:
        raise ValueError("SDK repository has no tags")
    output = {"schema_version": 1, "repository": repository, "sdks": {}, "configurations": {}}
    versions = sorted({_source_version(sdk, git(sdk, "rev-parse", "refs/tags/" + tag + "^{commit}")) for tag in tags})
    kernel_refs = _kernel_tag_refs(kernel_git, versions)
    missing_kernel_tags = sorted(set(versions) - set(kernel_refs))
    if missing_kernel_tags:
        raise ValueError("kernel source tags not found: " + ", ".join(missing_kernel_tags))
    kernel_repository = kernel_repository or kernel_git
    if Path(kernel_git).exists() and kernel_repository == kernel_git:
        try:
            kernel_repository = git(kernel_git, "config", "--get", "remote.origin.url")
        except subprocess.CalledProcessError:
            raise ValueError("local kernel cache needs --kernel-repository URL")
    for tag in sorted(tags):
        ref = git(sdk, "rev-parse", f"refs/tags/{tag}^{{commit}}")
        files = _tree(sdk, ref)
        try:
            source_version = _source_version(sdk, ref)
            kernel_ref = kernel_refs[source_version]
        except (ValueError, subprocess.CalledProcessError) as exc:
            raise ValueError(f"{tag}: cannot resolve immutable kernel source: {exc}") from exc
        models = {}
        configs = sorted(path for path in files if path.startswith("target/linux/") and path.endswith("/ndwrt.config"))
        if not configs:
            raise ValueError(f"{tag}: no tracked target/linux/**/ndwrt.config files")
        for path in configs:
            name = path.split("/")[-2]
            if not MODEL_RE.fullmatch(name):
                models[name] = {"status": "unsupported", "reason": f"unsupported model ID {name!r}; expected KN-####: {path}"}
                continue
            try:
                model, key, config = _model_entry(sdk, ref, files, path, kernel_ref)
                config["kernel_source_version"] = source_version
                key = canonical_hash(config)
                models[model] = {"configuration": key, "status": "supported"}
                record = {"sdk_input_key": key, "sdk_ref": ref, "sdk_tag": tag,
                          "kernel_repository": kernel_repository, "kernel_ref": kernel_ref,
                          "kernel_source_version": source_version, "kernel_patchver": config["kernel_patchver"],
                          "model": model, "board": config["board"], "arch": config["arch"],
                          "config": path, "config_sha256": config["config_sha256"],
                          "input_identity": {"sdk_build_tree_sha256": config["sdk_build_tree_sha256"],
                                             "board_makefile_sha256": config["board_makefile_sha256"],
                                             "scope": config["input_scope"]}}
                output["configurations"].setdefault(key, record)
            except (ValueError, subprocess.CalledProcessError) as exc:
                models[name] = {"status": "unsupported", "reason": str(exc)}
        series = re.match(r"^(\d+\.\d+)", tag)
        output["sdks"][tag] = {"ref": ref, "series": series.group(1) if series else "unknown",
                               "kernel_ref": kernel_ref, "kernel_source_version": source_version,
                               "models": {key: models[key] for key in sorted(models)}}
    return output


def verify_configuration(sdk, configuration):
    """Recompute the matrix input key from the exact SDK checkout before build."""
    ref, tag = configuration.get("sdk_ref"), configuration.get("sdk_tag")
    if git(sdk, "rev-parse", "HEAD") != ref:
        raise ValueError("SDK checkout ref differs from descriptor")
    if git(sdk, "rev-parse", f"refs/tags/{tag}^{{commit}}") != ref:
        raise ValueError("SDK tag does not resolve to descriptor ref")
    version = _source_version(sdk, ref)
    if version != configuration.get("kernel_source_version"):
        raise ValueError("SDK kernel source version differs from descriptor")
    files = _tree(sdk, ref)
    model, _, identity = _model_entry(sdk, ref, files, configuration.get("config", ""), configuration.get("kernel_ref"))
    identity["kernel_source_version"] = version
    key = canonical_hash(identity)
    for field, actual in (("sdk_input_key", key), ("model", model), ("board", identity["board"]),
                          ("arch", identity["arch"]), ("config_sha256", identity["config_sha256"])):
        if configuration.get(field) != actual:
            raise ValueError(f"descriptor {field} differs from exact SDK checkout")
    return key


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path.is_symlink():
        raise ValueError(f"refusing symlink output: {path}")
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(data)
        os.replace(temp, path)
    except Exception:
        Path(temp).unlink(missing_ok=True)
        raise
    return sha256(data.encode())
