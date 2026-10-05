# keenpbr-kmod implementation plan

Planning: Sol. Implementation: Luna. Every task uses ToDo/WIP/Done; live evidence is in STATUS.md.

## Scope and contract

Build standalone GPL-2.0 Linux 4.9 Keenetic modules with no policy engine or private userspace protocol. Separate IPv4/IPv6 modules expose legacy xtables table `keenpbr`, only PREROUTING, independent unload and per-network-namespace lifecycle. Default priority -149 (mangle + 1), build-time modes raw (-300), after-raw (-299), before-mangle (-151), after-mangle (-149). Record exact numeric priority, version and API contract 1 in metadata/manifest; raw is a hardware experiment, not a production inference.

Do not modify keen-pbr userspace or publish remotely in this task. Unknown models and experimental mappings must not acquire verified status from compilation, ELF equality or vermagic. Hardware checks remain ToDo until actual evidence exists.

## Shared implementation interfaces

Use JSON syntax in `targets/groups.yaml`, `targets/models.yaml` and `sdk.lock`: JSON is valid YAML and Python stdlib json avoids a new dependency. README must explain the format.

`sdk.lock`: `{"repository":"https://github.com/keenetic/keenetic-sdk.git","ref":"5ff3bfda8b7f38004f9fd6d4effc6bdaedf01e05","branch":"4.03","kernel":"4.9-ndm"}`. This immutable 4.03 revision contains all nine representative configs; main does not. Existing SDK checkout must match ref, reject mismatches; local generated build files are allowed, tracked SDK changes must not silently alter provenance. No automatic kernel ABI patches.

`groups.yaml`: `{"groups": {"mt7621": {"representative":"KN-1810","arch":"mipsel","aliases":[],"ipv6":true}, ...}}`. Nine groups: mt7988 KN-1812 aarch64; mt7622 KN-1811 aarch64; mt7981 KN-3811 aarch64; mt7621 KN-1810 mipsel; mt7628 KN-1212 mipsel; mt7621-highmem KN-1011 mipsel; en7528 KN-1912 mipsel; en7512 KN-2010 mips; en7516 KN-2112 mips. `models.yaml`: `{"models": {"KN-1810": {"group":"mt7621","status":"experimental","evidence":"SDK representative; hardware validation pending"}, ...}}`. Include supplied alias candidates as experimental, distinct from confirmed aliases; group aliases must be empty unless compatibility evidence specifically supports this project. Validate all references/status values and unique models.

Public commands:

- `scripts/prepare-sdk.sh` uses `SDK_DIR` or repository `.cache/keenetic-sdk`, checks exact lock and clones/checks out only missing SDK.
- `scripts/build.sh <group|KN-model>` uses known mapping only; `SDK_DIR`, `OUT_DIR` default repo/out, `JOBS` bounded default, `KEENPBR_PRIORITY_MODE` default after-mangle. Configure representative even when alias used; experimental mapping is a build request, never runtime authorization.
- Recipe installed as `SDK/package/kernel/keenpbr-table/Makefile`, `src/`, `LICENSE`, `VERSION`. `CONFIG_PACKAGE_kmod-keenpbr-table=m`, `make defconfig`, `make target/linux/compile`, clean/recompile package with numeric `KEENPBR_PRIORITY` and `KEENPBR_VERSION` arguments. Use SDK KERNEL_MAKEOPTS. No AUTOLOAD. IPv6 optional when actual CONFIG_IP6_NF_IPTABLES absent; IPv4 must remain buildable.
- `scripts/inspect-module.sh <module.ko> [audit-dir]`: saves modinfo, ELF header/symbols/versions and undefined-symbol output, fails missing essential audit tools. Cross nm is needed for MIPS; readelf is arch-independent. Handle __versions absence explicitly, not as ignored errors.
- `scripts/build-all.sh`: nine matrix entries from config, continue collecting failures, nonzero overall failure, write `OUT_DIR/build-report.txt`.
- `scripts/compare-modules.sh [OUT_DIR]`: candidate equality only; fingerprint allocatable executable/data sections, relocation/symbol identity, normalized modinfo, undefined symbols, architecture, endian, vermagic and __versions. Whole file SHA retained separately. Do not claim ABI compatibility or update mappings.
- `scripts/generate-manifest.py [--out OUT_DIR] [--release-dir PATH]`: output flattened `iptable_keenpbr-<group>.ko`, IPv6 counterpart when supported, manifest.json, SHA256SUMS. Default release-dir `OUT_DIR/release`. Fail missing matrix outputs, stale hashes, mixed SDK/version/priority/config provenance, unknown groups and unsafe names. Partial preview may be supported explicitly but release default requires all groups.

Build output `OUT_DIR/<group>/iptable_keenpbr.ko`, optional ip6table counterpart, metadata.json, audit/ and SHA256SUMS. Metadata minimum: `group`, `representative`, `arch`, `kernel`, `sdk_ref`, `version`, `priority_mode`, `priority`, `table_abi` (1), `kernel_config_sha256`, `module_symvers_sha256`, `modules`. Modules mapping keys `ipv4`/`ipv6`; each object has `file`, `sha256`, `size`, `vermagic`, `version`, `undefined_symbols`, `fingerprint`; IPv6 absence documented explicitly. Generation must validate bytes and emitted filenames. Release manifest includes `schema_version`, `version`, `sdk`, `contract`, `groups`, `models`, truthful compatibility/evidence. SHA256SUMS covers modules and manifest, never itself.

## Tasks and acceptance criteria

| ID | Status | Work | Acceptance |
|---|---|---|---|
| P01 | Done | Primary-source research, pinned SDK and API audit | Exact reference URLs; actual pinned kernel source APIs checked, extension restrictions recorded |
| P02 | Done | Plan and status documents, shared interfaces | PLAN.md and STATUS.md written before Luna implementation |
| K01 | Done | Minimal PREROUTING-only IPv4/IPv6 kernel code | net_generic state, pernet init/exit, table/hook setup, complete init failure cleanup, no netns layout changes |
| K02 | Done | VERSION, common build contract and SDK KernelPackage | GPL provenance retained, separate .ko files, compile-time modes, IPv6 optional, no auto-load |
| B01 | Done | Pinned SDK preparation and single-group build | Wrong ref/unknown group rejected; only actual fresh artifacts; kernel config/Symvers evidence |
| B02 | Done | ABI inspection and candidate binary comparison | ELF class/endian/arch checked; vermagic/kernel/module version checked; meaningful sections and relocations hashed |
| B03 | Done | Full matrix orchestration and release generation | All groups reported; errors propagated; strict safe manifest/model mapping and SHA256SUMS |
| T01 | Done | Nine groups and initial model status | No unsupported compatibility promotion; candidate aliases clearly experimental |
| T02 | Done | Host checks and regression tests | Five stdlib tests, runtime identity refusal, shellcheck and syntax checks |
| T03 | Done | Real pinned SDK KN-1810 build | Final-source IPv4/IPv6 modules compiled and audited at priority -149; see out/build-report.txt |
| T04 | Done | Real pinned SDK ARM64 representative build | KN-1812 IPv4/IPv6 compile and ABI inspection complete; no hardware claim |
| T05 | Done | Final-source full nine-group SDK matrix build | 9/9 groups, 18 modules, strict 20-asset manifest, matching source/kernel pins and verified SHA256SUMS |
| C01 | Done | PR CI: source checks + two representative builds | KN-1810 and KN-1812 dynamically derived; immutable SDK cache key and no release privileges |
| C02 | Done | Full nightly/release CI and aggregation | Nine group matrix from config; isolated SDK build cache; exact artifacts; tag VERSION validation; release only on authorized tag event |
| H01 | Done | Real-device smoke-test tooling | IPv4/IPv6 chain/restore/MARK/ipset/dscp/ports/counters checks; narrow cleanup traps; exact model/artifact validation |
| H02 | Done | Real-device priority experiment tooling | External ingress packet counter evidence; scoped mangle and keenpbr marks; no local OUTPUT assumption |
| H03 | ToDo | Hardware verification and compatibility promotion | Actual model, firmware, module SHA, priority, packet evidence recorded; hardware inaccessible means pending |
| D01 | Done | README, license, references, build/runtime instructions | Clearly list extension table restrictions, kernel/firmware caveats, hardware limits and userspace integration contract |
| V01 | Done | Final verification and status reconciliation | Host tests, runtime refusal, lint/syntax, manifest and checksum checks pass; hardware remains pending |

## Runtime and semantic pitfalls

Upstream raw uses fields in `net->ipv4`/`net->ipv6`; external modules cannot add these. Use `pernet_operations.id/.size`, `net_generic()` and family-specific table pointer state. The hook callback obtains the current namespace from state->net and reads its own net_generic table pointer; no shared ops.priv table pointer is needed. Read pinned ipt_register_table/ip6t_register_table: signatures and hook registration ownership may differ from newer kernels. No custom table global pointer shared across namespaces.

Legacy extensions enforce permitted table names in xt_check_target. Lowercase `-m dscp` match works on any table; uppercase `-j DSCP`/`TOS` targets are mangle-only in upstream 4.9. MARK, connmark/CONNMARK, set match, multiport and conntrack need pinned-source verification. Test dscp match used by keen-pbr; explicitly document unsupported mangle-only targets. Do not disguise keenpbr as mangle or patch SDK extension restrictions. Sources mention raw without conntrack; priority modes change conntrack availability.

A priority test must send packets from outside the router. Add scoped rules for a supplied source/interface/port, choose unused mark bits, observe PREROUTING after keenpbr, assert counters and mark B, remove exact temporary rules only. Connection Policy/mangle rebuild and hardware acceleration can alter behavior; mark those hardware-only tests pending. Smoke test must never flush existing table/policy or unload a module preloaded by another owner. Build-time/module sanity and known model checks precede explicit test loading; experimental requires operator opt-in. No remote router mutation in this implementation session.

## Source references

- [keen-pbr backend](https://github.com/maksimkurb/keen-pbr), [RAW introduction](https://github.com/maksimkurb/keen-pbr/commit/e2674cc79b18f88b4c84e6bfc3a14b90712e3eb0).
- [Pinned SDK 4.03](https://github.com/keenetic/keenetic-sdk/tree/5ff3bfda8b7f38004f9fd6d4effc6bdaedf01e05), configure.sh, include/kernel.mk, include/kernel-defaults.mk and model ndwrt.config.
- [AWG matrix](https://github.com/hoaxisr/awg-manager/blob/9c3dab0b4dd84710e4e21c979fab5cbf75e5eb01/scripts/build-kmods.sh), [KernelPackage](https://github.com/hoaxisr/awg-manager/blob/9c3dab0b4dd84710e4e21c979fab5cbf75e5eb01/kmod/awg-proxy/package/Makefile), [ABI evidence](https://github.com/hoaxisr/awg-manager/blob/9c3dab0b4dd84710e4e21c979fab5cbf75e5eb01/prebuilt/kmod/README.md), loader.go, soc.go.
- [IPv4 raw](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/netfilter/iptable_raw.c), [IPv6 raw](https://github.com/torvalds/linux/blob/v4.9/net/ipv6/netfilter/ip6table_raw.c), [IPv4 core](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/netfilter/ip_tables.c), [IPv6 core](https://github.com/torvalds/linux/blob/v4.9/net/ipv6/netfilter/ip6_tables.c), [xtables core](https://github.com/torvalds/linux/blob/v4.9/net/netfilter/x_tables.c).
- Linux 4.9 mangle tables, IPv4/IPv6 priority headers and xt_mark/xt_set/xt_dscp/xt_DSCP/xt_multiport/xt_conntrack/xt_connmark verify semantics, not binary compatibility.

Primary source snapshots available locally in `/tmp/keenpbr-references`; pinned SDK kernel investigation results will be added below. QEMU cannot establish proprietary Keenetic kernel ABI/hardware compatibility; add a documented optional test path only if a matching runnable image becomes available.

## Completed pinned-kernel API audit

SDK 4.03 points to [keenetic/kernel-49 tag 4.9.337-119](https://github.com/keenetic/kernel-49/tree/4.9.337-119), currently resolving to immutable commit `113cc622b3c48876927ae3c8db2e83fef4505fbf`. Its actual ip_tables.c, ip6_tables.c, raw tables, x_tables.c/headers, MARK/CONNMARK/dscp/DSCP/set extensions were downloaded and read under `/tmp/keenpbr-references/keenetic-*`.

- `ipt_register_table(net, template, replace, hook_ops, &table_pointer)` returns int and writes the pointer before registering hooks; matching unregister takes net, table pointer, ops. IPv6 has corresponding five-argument registration. `ipt_do_table(skb, state, table_pointer)` has three arguments.
- `xt_hook_ops_alloc()` derives family, hook mask and priority from the template; hook callbacks can use `net_generic(state->net, pernet_id)` with no changes to the kernel netns structures. Use `.init` for eager namespace registration plus template `.table_init` for core compatibility; registration helper should return success if the namespace table is already present. On unregister, hooks cease before freeing the table.
- Keenetic raw code differs from upstream: separate raw/raw_out table templates and priorities. Do not copy the raw_out behavior; keenpbr is exclusively PREROUTING.
- Pinned MARK and CONNMARK have no table-name restriction. `-m dscp` and `-m set` also have none. `-j DSCP` and `-j TOS` require mangle. `SET --map-set` explicitly requires mangle even though add/delete operations do not. Document these limits accurately; no extension ABI patch is justified.
- SDK pin fixes build recipes but the recipes download a kernel tag and prebuilt toolchain release. Record kernel commit/tag and archive SHA plus toolchain identity if obtainable; do not claim bit-for-bit reproducibility from SDK ref alone. Source download validation must fail checksum mismatches when recorded. Hardware firmware version compatibility remains unproven.

Parent successfully configured KN-1810 in a Debian container using the pinned SDK and started kernel compilation independently of module source. This is configuration evidence only; compilation and hardware tasks retain their own status.
