# keenpbr-kmod

Build and audit separate IPv4 and IPv6 modules for the Keenetic `keenpbr`
xtables table. The table runs only at PREROUTING and uses ordinary xtables
rules. Routing policy stays in the separate `keen-pbr` userspace project; this
repository defines no private kernel/userspace protocol.

## Compatibility

Runtime selection uses the exact Keenetic model ID and full OS release. It
does not guess from SoC, architecture, kernel release, nearby SDK tags, or
module fingerprints. Every accepted mapping currently starts as
`experimental`; compilation and ABI audits do not establish hardware
compatibility. `verified` requires a test on that exact router model.

IPv4 requires the SDK kernel configuration to provide `CONFIG_IP_NF_IPTABLES`.
IPv6 is built only when `CONFIG_IP6_NF_IPTABLES` is enabled; a missing IPv6
module is recorded with the build's audited reason.

## All-tag build and snapshot

The committed [`kernel-matrix.json`](kernel-matrix.json) maps every published
SDK tag and model to immutable SDK/kernel commits, an exact configuration, and
an explicit supported or unsupported outcome. Equal full build inputs share a
content-addressed build key. The SDK-tree identity is intentionally
conservative: changes to tracked SDK inputs can cause extra builds.
The matrix uses schema version 1: `sdks[exact_tag].models[exact_model]` points
to a configuration key in `configurations[sdk_input_key]`. Planning writes
`out/plan.json` and `out/descriptors/<build_key>.json`.

Refresh the matrix locally with Git and Python 3:

```sh
python3 scripts/refresh-matrix.py \
  --sdk https://github.com/keenetic/keenetic-sdk.git \
  --kernel-git https://github.com/keenetic/kernel-49.git \
  --repository https://github.com/keenetic/keenetic-sdk.git \
  --output kernel-matrix.json
```

This fetches all SDK tags and resolves their pinned kernel source tags. The
scheduled/manual [matrix workflow](.github/workflows/refresh-matrix.yml)
regenerates the file, commits only a changed matrix to `main`, then dispatches
the build workflow with that exact commit SHA.

Descriptor builds require the pinned amd64 Debian/Python/GCC environment in
`.ci/build-environment.json`. Use the same image locally so the build host and
reproducibility settings match CI. Repository scripts use Python 3.14; SDK
commands use Debian Python 3.11 with `distutils` from the pinned apt snapshot:

```sh
docker run --rm -it --platform linux/amd64 \
  -v "$PWD:/workspace" -w /workspace \
  python:3.14.2-slim-bookworm@sha256:e87711ef5c86aaeaa7031718a69db79d334d94c545c709583f651b8185870941 \
  bash
```

Inside the container, install the pinned packages and plan the matrix:

```sh
.ci/setup-build-env.sh
python3 scripts/plan-builds.py --matrix kernel-matrix.json \
  --descriptors out/descriptors --output out/plan.json
mkdir -p out
chown -R builder:builder out
```

Run each shard listed in `out/plan.json` as UID 1000 (`builder`); each key
uses the isolated, fixed `/build/sdk` checkout in sequence:

```sh
runuser --user builder -- env JOBS=4 python3 scripts/build-snapshot.py \
  --plan out/plan.json --descriptors out/descriptors --shard 0 --out out
```

The plan writes one descriptor per unique build key and divides work into at
most 256 shards. Each shard builds its keys serially. Build results go under
`out/builds/<build_key>/` and include modules, checksums, metadata, and audit
evidence. The current matrix has 3,475 unique configurations, so the initial
backfill is substantial. Exact builds from a complete published snapshot can
be reused after the prior manifest, matrix, checksums, provenance, and module
bytes pass validation. CI caches downloaded SDK archives only, with SDK checksum
and kernel-commit checks on reuse. Toolchains, configuration, and kernel build
state are recreated for unmatched keys; staging directories are never cached.

Assemble only after every planned build has succeeded and passed its audit:

```sh
python3 scripts/assemble-release.py --matrix kernel-matrix.json \
  --plan out/plan.json --builds-dir out/builds \
  --output-dir out/snapshots --notes-file out/release-notes.md \
  --repository https://github.com/maksimkurb/keen-pbr-kmod-keenetic \
  --reuse-index out/reuse-index
```

The resulting `modules-<version>-<digest>/` snapshot contains uniquely
content-addressed IPv4/IPv6 modules, the exact `kernel-matrix.json`, a
schema-version-2 `manifest.json`, and `SHA256SUMS`. The manifest maps
`releases[exact_full_OS_release][exact_model]` to status, full build key, and
per-family filename, SHA256, vermagic, and version. `builds[build_key]` keeps
the SDK, kernel, configuration, and build-input provenance. It records
IPv6-unavailable reasons and unsupported mappings explicitly.

The [build workflow](.github/workflows/build.yml) runs lightweight source,
shell, and runtime-safety checks on pull requests. A push to `main` or manual
dispatch checks out one exact commit, builds every uncovered configuration,
and validates complete matrix coverage before automatically publishing the
content-addressed GitHub release. A retry validates an identical published
snapshot instead of creating a duplicate. The scheduled/manual
[matrix workflow](.github/workflows/refresh-matrix.yml) dispatches this build
for the exact commit after it pushes a changed matrix.

## Runtime selection

`scripts/select-module.py` performs exact model/release/family lookup without
loading a module. On a router, `--detect` calls `ndmc -c 'show version'` to
read `hw_id` and the full release. It only normalizes `KN1810` to `KN-1810`.
Unknown releases/models, unsupported families, invalid artifact hashes, and
experimental mappings without opt-in return an unavailable result with the
fallback order `custom -> raw -> mangle`.

For an explicit lookup:

```sh
python3 scripts/select-module.py --manifest manifest.json \
  --model KN-1810 --release 4.03.C.2.0-1 --family ipv4
```

This read-only lookup accepts an untrusted manifest and reports
`trusted_manifest: false`. To verify the selected bytes against a trusted
manifest, provide its expected digest and the directory containing snapshot
modules. Preflight also checks the module's `vermagic` kernel release against
`uname -r` from `--detect`; for manual lookup, pass that value with
`--kernel-release`:

```sh
python3 scripts/select-module.py --manifest manifest.json \
  --manifest-sha256 "$(sha256sum manifest.json | awk '{print $1}')" \
  --artifacts modules-<version>-<digest> --detect --family ipv4 \
  --allow-experimental
```

The command emits JSON with the selected filename, family SHA256, build key,
status, contract, and manifest/build provenance. Artifact preflight requires
`--manifest-sha256`; it checks bytes but does not run `insmod` or establish
hardware compatibility. Consumers must keep their existing fallback behavior
when selection is unavailable.

## Local diagnostic builds and legacy smoke tools

The older pinned-SDK helpers remain useful for one-model diagnostics; they are
separate from the all-tag snapshot pipeline:

```sh
./scripts/prepare-sdk.sh
./scripts/build.sh mt7621
./scripts/build.sh --sdk-model KN-1810
```

`scripts/discover-models.py` and `scripts/build-models.py` inspect/build models
from the single SDK in `sdk.lock`. The old `scripts/generate-manifest.py`
creates a schema-version-1 nine-group manifest. `smoke-test.sh` and
`priority-test.sh` also accept only that schema-version-1 manifest; they do not
consume the new all-tag schema-version-2 snapshot. Keep these scripts for
local/router diagnostics only, not as the current release or selection path.

For a legacy router check, copy a schema-version-1 manifest and its matching
group module to the router, then run the helpers with an externally generated
ingress packet. Reserve the mark bits used by the test:

```sh
sh scripts/smoke-test.sh manifest.json "$(sha256sum manifest.json | awk '{print $1}')" \
  KN-1810 ipv4 iptable_keenpbr-mt7621.ko eth0 198.51.100.2 443 \
  0x10000000 0x30000000 --allow-experimental
sh scripts/priority-test.sh manifest.json "$(sha256sum manifest.json | awk '{print $1}')" \
  KN-1810 ipv4 iptable_keenpbr-mt7621.ko eth0 198.51.100.2 443 \
  0x30000000 0x10000000 0x20000000 --allow-experimental
```

Replace the interface and source with the router's ingress values and send a
TCP packet through the router to a forwarded host on port 443. These checks
load a module and test rules; they do not change vendor rules or promote any
model beyond the exact hardware evidence collected.

`priority-test.sh` checks PREROUTING order by observing the mark at a later
filter hook; local OUTPUT traffic cannot establish that order. These checks can
support `verified` status only for the exact tested model. QEMU is not evidence
here because no matching Keenetic kernel image or emulation setup is provided.

## Table behavior and rule limits

The table is named `keenpbr`, separate from the vendor `mangle` table. Use
standard tools such as `iptables -t keenpbr` and `ip6tables -t keenpbr`.
Default priority is `NF_IP_PRI_MANGLE + 1` (-149), after Keenetic mangle
processing and before DNAT (-100), subject to real-router confirmation.

Pinned Linux 4.9 extensions allow MARK/CONNMARK targets, `-m set`, `-m dscp`,
`-m multiport`, and conntrack matches. The uppercase `-j DSCP`, `-j TOS`, and
`-j SET --map-set` targets require `mangle` and are unavailable in `keenpbr`.
At raw priority conntrack has not run, so conntrack matching is unavailable.

Module version is independent of the `keen-pbr` userspace version. Table ABI is
1. Read-only priority and ABI parameters are available under
`/sys/module/iptable_keenpbr/parameters/` (use `ip6table_keenpbr` for IPv6); the
same metadata is available through `modinfo`.

## References

- [`keen-pbr` firewall backend](https://github.com/maksimkurb/keen-pbr/tree/master/src/firewall)
  and [RAW PREROUTING introduction](https://github.com/maksimkurb/keen-pbr/commit/e2674cc79b18f88b4c84e6bfc3a14b90712e3eb0).
- [Keenetic SDK 4.03 pinned revision](https://github.com/keenetic/keenetic-sdk/tree/5ff3bfda8b7f38004f9fd6d4effc6bdaedf01e05)
  and its `configure.sh`, `include/kernel.mk`, and per-model kernel configs.
- [AWG Manager pinned kmod matrix](https://github.com/hoaxisr/awg-manager/blob/9c3dab0b4dd84710e4e21c979fab5cbf75e5eb01/scripts/build-kmods.sh),
  [KernelPackage example](https://github.com/hoaxisr/awg-manager/blob/9c3dab0b4dd84710e4e21c979fab5cbf75e5eb01/kmod/awg-proxy/package/Makefile),
  and [compatibility notes](https://github.com/hoaxisr/awg-manager/blob/9c3dab0b4dd84710e4e21c979fab5cbf75e5eb01/prebuilt/kmod/README.md).
- [Keenetic kernel 4.9.337-119 source](https://github.com/keenetic/kernel-49/tree/4.9.337-119):
  [IPv4 raw table](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/ipv4/netfilter/iptable_raw.c),
  [IPv6 raw table](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/ipv6/netfilter/ip6table_raw.c),
  [IPv4 iptables core](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/ipv4/netfilter/ip_tables.c),
  [IPv6 iptables core](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/ipv6/netfilter/ip6_tables.c),
  and [x_tables core](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/x_tables.c).
- Linux 4.9 [hook priorities](https://github.com/keenetic/kernel-49/blob/4.9.337-119/include/uapi/linux/netfilter_ipv4.h),
  [MARK](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_mark.c),
  [set](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_set.c),
  [DSCP match](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_dscp.c),
  [DSCP target](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_DSCP.c),
  [conntrack](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_conntrack.c),
  and [CONNMARK](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_connmark.c).

License: GPL-2.0-only. See [`LICENSE`](LICENSE).
