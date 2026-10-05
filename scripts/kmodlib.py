#!/usr/bin/env python3
"""Small stdlib helpers shared by the Keenetic build and release scripts."""
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUP_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MODEL_RE = re.compile(r"^KN-[0-9]{4}$")
ARCHES = {"mipsel": ("ELF32", "2's complement, little endian", "MIPS"),
          "mips": ("ELF32", "2's complement, big endian", "MIPS"),
          "aarch64": ("ELF64", "2's complement, little endian", "AArch64")}
PRIORITIES = {"raw": -300, "after-raw": -299, "before-mangle": -151, "after-mangle": -149}


def config(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read JSON-compatible YAML {path}: {exc}") from exc


def matrix():
    groups = config(ROOT / "targets/groups.yaml").get("groups")
    models = config(ROOT / "targets/models.yaml").get("models")
    if not isinstance(groups, dict) or not isinstance(models, dict) or not groups:
        raise ValueError("groups.yaml and models.yaml must contain non-empty objects")
    seen = set()
    for group, item in groups.items():
        if not GROUP_RE.fullmatch(group) or not isinstance(item, dict):
            raise ValueError(f"unsafe or malformed group: {group!r}")
        if item.get("arch") not in ARCHES or not MODEL_RE.fullmatch(item.get("representative", "")):
            raise ValueError(f"invalid architecture/representative for {group}")
        if not isinstance(item.get("ipv6"), bool):
            raise ValueError(f"{group}: ipv6 must be boolean")
    for model, item in models.items():
        if not MODEL_RE.fullmatch(model) or not isinstance(item, dict):
            raise ValueError(f"unsafe or malformed model: {model!r}")
        if item.get("group") not in groups or item.get("status") not in {"verified", "compatible", "experimental", "unsupported"}:
            raise ValueError(f"invalid group/status for {model}")
    for group, item in groups.items():
        model = item["representative"]
        if model in seen or models.get(model, {}).get("group") != group:
            raise ValueError(f"representative mapping mismatch or duplicate: {model}")
        seen.add(model)
    return groups, models


def resolve_target(target):
    groups, models = matrix()
    if target in groups:
        return target, groups[target]
    if target in models:
        item = models[target]
        if item["status"] == "unsupported":
            raise ValueError(f"{target} is unsupported")
        group = item["group"]
        return group, groups[group]
    raise ValueError(f"unknown group/model: {target}")


def run(args, *, cwd=None, check=True, capture=True):
    result = subprocess.run(args, cwd=cwd, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, args))}\n{result.stdout or ''}")
    return result.stdout or ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_sha256(root=ROOT):
    """Hash exactly the tracked inputs copied into a KernelPackage build."""
    import hashlib
    root = Path(root)
    files = sorted((root / "src").rglob("*")) + [root / "package/Makefile", root / "LICENSE", root / "VERSION"]
    digest = hashlib.sha256()
    for path in sorted(p for p in files if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def tool(name, required=True):
    found = shutil.which(name)
    if required and not found:
        raise ValueError(f"required audit tool not found: {name}")
    return found


def elf_identity(path):
    hdr = run([tool("readelf"), "-h", str(path)])
    fields = {}
    for line in hdr.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def check_arch(path, arch):
    fields = elf_identity(path)
    expected = ARCHES[arch]
    actual = (fields.get("Class"), fields.get("Data"), fields.get("Machine"))
    machine_ok = actual[2].startswith("MIPS") if arch in {"mips", "mipsel"} and actual[2] else actual[2] == expected[2]
    if actual[:2] != expected[:2] or not machine_ok:
        raise ValueError(f"{path}: ELF architecture {actual!r}; expected {expected!r}")
    if fields.get("Type") != "REL (Relocatable file)":
        raise ValueError(f"{path}: expected a relocatable kernel module ELF")
    return fields


def undefined_symbols(path):
    candidates = [tool("nm", required=False), tool("mipsel-openwrt-linux-nm", required=False),
                  tool("mips-openwrt-linux-nm", required=False), tool("aarch64-openwrt-linux-nm", required=False)]
    for nm in dict.fromkeys(x for x in candidates if x):
        try:
            return run([nm, "-u", str(path)])
        except RuntimeError:
            pass
    raise ValueError("unable to inspect undefined symbols with host or Keenetic cross nm")


def audit_module(path, audit_dir, arch=None):
    path = Path(path)
    audit_dir = Path(audit_dir)
    audit_dir.mkdir(parents=True, exist_ok=True)
    readelf, modinfo = tool("readelf"), tool("modinfo")
    header = run([readelf, "-h", str(path)])
    symbols = run([readelf, "-sW", str(path)])
    sections = run([readelf, "-SW", str(path)])
    relocs = run([readelf, "-rW", str(path)])
    has_versions = "__versions" in sections
    versions = run([readelf, "-x", "__versions", str(path)]) if has_versions else "__versions absent\n"
    undefined = undefined_symbols(path)
    info = run([modinfo, str(path)])
    (audit_dir / "readelf-header.txt").write_text(header)
    (audit_dir / "readelf-sections.txt").write_text(sections)
    (audit_dir / "readelf-symbols.txt").write_text(symbols)
    (audit_dir / "readelf-relocations.txt").write_text(relocs)
    (audit_dir / "readelf-versions.txt").write_text(versions if versions.strip() else "__versions absent\n")
    (audit_dir / "undefined-symbols.txt").write_text(undefined)
    (audit_dir / "modinfo.txt").write_text(info)
    fields = elf_identity(path)
    if arch:
        check_arch(path, arch)
    values = {}
    for key in ("vermagic", "version", "description", "license", "keenpbr_priority", "keenpbr_table_abi"):
        result = run([modinfo, "-F", key, str(path)], check=False).strip()
        values[key] = result or None
    values["undefined_symbols"] = sorted(line.split()[-1] for line in undefined.splitlines() if line.split())
    values["size"] = path.stat().st_size
    values["sha256"] = sha256(path)
    values["elf"] = {k: fields.get(k) for k in ("Class", "Data", "Machine", "Type")}
    return values


def fingerprint(path):
    """Hash load-relevant section contents and ABI evidence, excluding debug/path data."""
    readelf, modinfo = tool("readelf"), tool("modinfo")
    hdr = elf_identity(path)
    arch = (hdr.get("Class"), hdr.get("Data"), hdr.get("Machine"))
    shdr = run([readelf, "-SW", str(path)])
    elf_header = run([readelf, "-h", str(path)])
    sections = {}
    # GNU readelf -SW: [Nr] Name Type Address Off Size ES Flg Lk Inf Al
    for line in shdr.splitlines():
        match = re.match(r"\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+([0-9a-fA-F]+)\s+\S+\s+([^\s]*)\s+\S+\s+\S+\s+(\S+)", line)
        if match:
            idx, name, typ, size, flags, align = match.groups()
            sections[idx] = name
            if "A" in flags and typ in {"PROGBITS", "NOBITS"}:
                sections[name] = (typ, int(size, 16), flags, align)
    elf_flags = re.search(r"^\s*Flags:\s*(.*)$", elf_header, re.M)
    pieces = [repr(arch), "elf-flags=" + (elf_flags.group(1).strip() if elf_flags else "")]
    for name, (typ, size, flags, align) in sorted((k, v) for k, v in sections.items() if isinstance(v, tuple)):
        pieces.append(f"section:{name}:{typ}:{size}:{flags}:{align}")
        if typ == "NOBITS":
            continue
        dump = run([readelf, "-x", name, str(path)], check=False)
        # Read whole bytes, including final words shorter than 32 bits.
        data = []
        for line in dump.splitlines():
            fields = line.split()
            if fields and re.fullmatch(r"0x[0-9a-fA-F]+", fields[0]):
                offset = int(fields[0], 16)
                remaining = min(16, max(0, size - offset))
                for word in fields[1:]:
                    if not re.fullmatch(r"[0-9a-fA-F]{2,8}", word) or len(word) % 2:
                        break
                    take = min(len(word), remaining * 2)
                    data.append(word[:take].lower())
                    remaining -= take // 2
                    if remaining <= 0: break
        pieces.append(name + ":" + "".join(data)[:size * 2])
    # Normalize relocations to allocated sections only; ignore debug relocation tables.
    relocations = run([readelf, "-rW", str(path)])
    active = False
    relrows = []
    for line in relocations.splitlines():
        title = re.search(r"Relocation section '([^']+)'", line)
        if title:
            section_name = title.group(1)
            rel_name = re.match(r"\.rela?(.+)", section_name)
            target = rel_name.group(1) if rel_name else section_name
            active = target in sections and isinstance(sections[target], tuple)
            continue
        if active:
            row = re.match(r"\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)\s+[0-9a-fA-F]+\s+(\S+)(.*)", line)
            if row:
                relrows.append(f"{target}:{row.group(1)}:{row.group(2)}:{row.group(3)}:{row.group(4).strip()}")
    pieces.append("\n".join(relrows))
    # Keep global/weak symbol identity, target section names and sizes.
    symtext = run([readelf, "-sW", str(path)])
    symrows = []
    for line in symtext.splitlines():
        m = re.match(r"\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)", line)
        if m and m.group(4) in {"GLOBAL", "WEAK"}:
            section = sections.get(m.group(6), m.group(6))
            symrows.append(f"{m.group(1)}:{m.group(2)}:{m.group(3)}:{m.group(4)}:{m.group(5)}:{section}:{m.group(7).strip()}")
    pieces.append("\n".join(sorted(symrows)))
    versions = run([readelf, "-x", "__versions", str(path)], check=False) if "__versions" in sections else "__versions absent"
    pieces.append(versions)
    pieces.append(undefined_symbols(path))
    for field in ("vermagic", "version", "license", "description", "depends", "keenpbr_priority", "keenpbr_table_abi"):
        pieces.append(field + "=" + run([modinfo, "-F", field, str(path)], check=False).strip())
    return hashlib.sha256("\n".join(pieces).encode()).hexdigest()
