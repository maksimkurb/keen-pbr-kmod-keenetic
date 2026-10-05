# keenpbr-kmod

Build and audit separate IPv4 and IPv6 Linux 4.9 modules for the Keenetic
`keenpbr` xtables table. The modules only register a PREROUTING table and run
ordinary xtables rules; routing policy stays in the `keen-pbr` userspace
project. This repository does not define a private kernel/userspace protocol.

## Compatibility status

Builds use the nine representative configs in [`targets/groups.yaml`](targets/groups.yaml).
The mapping in [`targets/models.yaml`](targets/models.yaml) is only a candidate
selection list. Compatibility status has four meanings:

- `verified`: this module was loaded and exercised on that exact real router model.
- `compatible`: its kernel group is confirmed, but this model has not had a device run.
- `experimental`: the mapping is a candidate and compatibility is unproven.
- `unsupported`: do not install or load the module.

All current model mappings are `experimental`, including build representatives.
Same SoC, ELF architecture or `vermagic` does not prove kernel ABI compatibility.
Do not treat a successful build or matching module fingerprint as hardware evidence.

`groups.yaml`, `models.yaml` and [`sdk.lock`](sdk.lock) contain JSON, which is a
valid YAML subset. This lets the build tools validate them using Python's
standard library without a YAML dependency. Keep model evidence explicit;
`groups.*.aliases` is empty until this project's hardware evidence supports
sharing a module.

## Build

Use a Debian/Ubuntu build host with a C/C++ toolchain, make, git, Python 3,
Perl, awk, flex, bison, gettext, rsync, unzip, `bc`, `gperf`, `attr`, `lzip`,
`protobuf-c-compiler`, `libhtml-parser-perl`, `libjson-perl`,
`libxml-libxml-perl`, zlib and ncurses development headers, `jq`, `xxd`,
`zstd`, and ELF inspection tools (`readelf`, `modinfo`, `nm`). The SDK's pinned
Linux 4.9 tree is old; GCC 12 is known to avoid the
`constexpr` parsing failure seen with newer host compilers. SDK toolchains and
kernel sources are fetched by the SDK during the first build.

```sh
./scripts/prepare-sdk.sh
./scripts/build.sh mt7621
./scripts/build.sh KN-1812
./scripts/build-all.sh
```

Set `SDK_DIR` to an existing checkout only when its `HEAD` exactly matches
`sdk.lock`; tracked modifications are rejected. Build artifacts go under
`out/<group>/`, including module audit data and metadata. Set `OUT_DIR` to
change the output root. `KEENPBR_PRIORITY_MODE` selects `raw`, `after-raw`,
`before-mangle`, or `after-mangle`; the default is `after-mangle` (-149). These
are build-time experiments, not runtime tuning knobs. `scripts/compare-modules.sh`
can identify binary-equality candidates; it cannot promote model compatibility.

The SDK repository ref is pinned to an immutable commit, and the build rejects
a kernel source checkout whose commit differs from the lock. Each group also
stores the exact kernel `.config`, `Module.symvers`, and module-source SHA256
under `out/<group>/audit/` and metadata. SDK download checksums and host
compiler/toolchain details still affect bit-for-bit reproducibility. Inspect
each output's metadata and ABI audit before using it.

## Table behavior and rule limits

The table is named `keenpbr` and runs only at PREROUTING. It is separate from
the vendor `mangle` table, so vendor ruleset rebuilds do not delete it. Rules
still use standard tools such as `iptables -t keenpbr` and
`ip6tables -t keenpbr`.

Pinned Linux 4.9 extensions allow MARK/CONNMARK targets, `-m set`, `-m dscp`,
`-m multiport`, and conntrack matches in this table. The lowercase `-m dscp`
match is supported. The uppercase `-j DSCP` and `-j TOS` targets, and
`-j SET --map-set`, require the `mangle` table and are not supported in
`keenpbr`. At `raw` priority, conntrack has not run yet; conntrack matching is
not available there. The selected priority is recorded in build metadata and
the release manifest.

The default hook priority is `NF_IP_PRI_MANGLE + 1` (-149), intended to run
after Keenetic mangle processing and before DNAT (-100). Actual packet order
and interaction with Connection Policy, hardware acceleration and firmware
must be checked on a real router before calling a model verified. Use the
documented hardware priority test; local OUTPUT traffic does not establish
PREROUTING order.

The module release version is independent of the `keen-pbr` userspace version.
The separate table contract is ABI 1; module releases can change without an
ABI change. The loaded module exposes its version and read-only priority and
ABI parameters at `/sys/module/iptable_keenpbr/version`,
`/sys/module/iptable_keenpbr/parameters/priority`, and
`/sys/module/iptable_keenpbr/parameters/table_abi` (use `ip6table_keenpbr`
for IPv6). The same build metadata is available through `modinfo -F version`,
`modinfo -F keenpbr_priority`, and `modinfo -F keenpbr_table_abi`.

## Release artifacts

The strict release generator emits one file per supported family and group:

```text
iptable_keenpbr-mt7621.ko
ip6table_keenpbr-mt7621.ko
manifest.json
SHA256SUMS
```

The manifest records group/model evidence, SDK and kernel identity, module
hashes, vermagic, module version, priority and table ABI. `SHA256SUMS` covers
the modules and manifest. Release CI builds the complete nine-group matrix;
GitHub Releases are created only from a version-matching `v*` tag. No release
or model is hardware verified until the corresponding router test is recorded.

After `build-all.sh`, generate the strict release directory with:

```sh
python3 scripts/generate-manifest.py
# Writes out/release/ by default; explicit form:
python3 scripts/generate-manifest.py --out out --release-dir out/release
```

The generator requires the complete matrix and matching source, SDK, kernel,
version, priority, module and audit hashes. A preview with only completed
groups requires the explicit `--partial` option and is not a release.

The final-source local build completed 9/9 kernel groups against SDK commit
`5ff3bfda8b7f38004f9fd6d4effc6bdaedf01e05` and kernel commit
`113cc622b3c48876927ae3c8db2e83fef4505fbf`, with source SHA256
`7dc1a6cce0b0a8455e7421429d4627cf4cf87e7f79576818d69445bee630fc4e`.
It produced 18 modules at the default after-mangle priority (-149); the strict
manifest check passed and all 19 `SHA256SUMS` entries verified. This is build
evidence only: current model mappings remain experimental, GitHub Actions has
not been run remotely, and no release has been published.

Binary comparison found equal fingerprints for the three ARM64 groups
`mt7988`/`mt7622`/`mt7981`, for `mt7621`/`en7528`, and for `en7512`/`en7516`.
These are candidates only; release artifacts and model mappings remain
separate per matrix group. A matching fingerprint does not establish ABI or
hardware compatibility.

The final-source KN-1810 raw-priority PoC also built both modules at -300 and
passed its partial manifest and checksum checks. Keep this experiment in a
separate output directory so its priority provenance cannot mix with the
default release build:

```sh
OUT_DIR=out/priority-raw KEENPBR_PRIORITY_MODE=raw ./scripts/build.sh mt7621
python3 scripts/generate-manifest.py --out out/priority-raw \
  --release-dir out/priority-raw/release --partial
```

This creates the isolated two-module preview at `out/priority-raw/release/`;
it does not change `out/release/`. The raw variant has not been tested on
hardware.

## Loading and hardware checks

Loading modules is a privileged router operation. The smoke-test helper checks
for an exact model mapping and requires explicit opt-in for experimental
models. It adds only its own test chains/rules and removes only those rules;
it must not flush the vendor table or unload a module owned by another
component. If no known model/group is available, userspace should keep using
its existing RAW/mangle backend. This repository does not implement or change
that userspace fallback.

On a real Keenetic, `smoke-test.sh` takes a release manifest and its SHA256,
model, family, module path, ingress interface, source address, TCP port, and
reserved mark/mask. It requires `--allow-experimental` for current mappings.
It loads the module and waits for an externally sent packet to increment its
scoped rule counter. For example, after copying the manifest and matching
module to the router:

```sh
sh scripts/smoke-test.sh manifest.json "$(sha256sum manifest.json | awk '{print $1}')" \
  KN-1810 ipv4 iptable_keenpbr-mt7621.ko eth0 198.51.100.2 443 \
  0x10000000 0x30000000 --allow-experimental
```

Replace the example ingress interface and source address with values for the
router and reserve the selected mark bits for this test.

`priority-test.sh` runs after the smoke test has loaded the same module. It
adds scoped temporary marks in `mangle` and `keenpbr`, sends external ingress
traffic through the router to a forwarded host, then checks the later filter
hook's observed mark. Reserve the supplied mask bits and use a real test path;
the helper removes only its own rules. For the default after-mangle priority,
the final mark should be `MARK_B`:

```sh
sh scripts/priority-test.sh manifest.json "$(sha256sum manifest.json | awk '{print $1}')" \
  KN-1810 ipv4 iptable_keenpbr-mt7621.ko eth0 198.51.100.2 443 \
  0x30000000 0x10000000 0x20000000 --allow-experimental
```

Send a TCP packet from that source through `eth0` to a forwarded host on port
443; replace the example interface and source with the real ingress values.

Do not infer router compatibility from QEMU: no matching Keenetic kernel image
or emulation setup is provided here. Hardware checks remain the source of
`verified` status.

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
  [x_tables core](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/x_tables.c).
- [Linux 4.9 hook priorities](https://github.com/keenetic/kernel-49/blob/4.9.337-119/include/uapi/linux/netfilter_ipv4.h)
  and extension implementations for [MARK](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_mark.c),
  [set](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_set.c),
  [DSCP match](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_dscp.c),
  [DSCP target](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_DSCP.c),
  [conntrack](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_conntrack.c),
  and [CONNMARK](https://github.com/keenetic/kernel-49/blob/4.9.337-119/net/netfilter/xt_connmark.c).

License: GPL-2.0-only. See [`LICENSE`](LICENSE).
