# Status

Task states: ToDo / WIP / Done. Planning is assigned to Sol; implementation to Luna.

| ID | Status | Evidence / next action |
|---|---|---|
| P01 | Done | Primary upstream/AWG sources and actual Keenetic kernel commit 113cc622b3c48876927ae3c8db2e83fef4505fbf inspected; pinned registration APIs and extension restrictions documented in PLAN.md |
| P02 | Done | PLAN.md includes shared config/metadata/CLI contracts and acceptance criteria |
| K01 | Done | Separate IPv4/IPv6 PREROUTING modules implemented with per-netns table state |
| K02 | Done | VERSION, Kbuild and SDK KernelPackage implemented; priority modes are compile-time |
| B01 | Done | SDK preparation and single-group build script verify SDK and kernel refs; actual KN-1810 package build is T03 |
| B02 | Done | ELF/ABI inspection and load-relevant candidate fingerprint scripts implemented |
| B03 | Done | Matrix reporting and strict full/partial manifest and checksum generation implemented |
| T01 | Done | Nine groups and 26 model candidates validate via stdlib JSON; all mappings remain experimental, SDK/kernel refs recorded |
| T02 | Done | Five stdlib build-tool tests and tests/runtime-safety.sh pass; CI runs both |
| T03 | Done | Final-source KN-1810 IPv4/IPv6 built (5668/5676 bytes), MIPS32 LE, vermagic `4.9-ndm-5 SMP mod_unload MIPS32_R2 32BIT`, version 0.1.0, priority -149; isolated raw -300 build and 3-entry PoC checksum passed at `out/priority-raw/release/`; source SHA256 `7dc1a6cce0b0a8455e7421429d4627cf4cf87e7f79576818d69445bee630fc4e` |
| T04 | Done | Final-source KN-1812 ARM64 IPv4/IPv6 built (8048/8056 bytes), vermagic `4.9-ndm-5 SMP mod_unload aarch64`, version 0.1.0, priority -149 |
| T05 | Done | Final-source matrix reports 9/9 groups, 18 modules and strict 20-asset release manifest; SDK ref `5ff3bfda8b7f38004f9fd6d4effc6bdaedf01e05`, kernel ref `113cc622b3c48876927ae3c8db2e83fef4505fbf`; 26 model mappings remain experimental |
| C01 | Done | PR workflow derives KN-1810 and KN-1812 representative builds from groups config; YAML parses, shell checks defined |
| C02 | Done | Nightly/full and tag release workflows derive all nine builds; release validates VERSION and publishes only on versioned tag |
| H01 | Done | Exact model/hash/version checks and scoped IPv4/IPv6 smoke-test tooling implemented; no device run |
| H02 | Done | External-ingress mangle-vs-keenpbr priority test tooling implemented; no device run |
| H03 | ToDo | Requires real Keenetic; no verified models yet |
| D01 | Done | README documents build, ABI/extension limits, compatibility status, runtime constraints and primary references; GPL-2 license included |
| V01 | Done | Five unit tests, runtime identity refusal, shellcheck/syntax, compileall, workflow YAML, strict manifest, and all 19 SHA256SUMS entries passed |

The final-source after-mangle matrix and isolated KN-1810 raw-priority PoC are validated. Binary equality groups are candidates only and remain separate in the manifest. Hardware verification (H03) remains pending, all 26 model mappings are experimental, GitHub Actions was not run remotely, and no release has been published.
