# Статус финального плана

Планирование: **Sol**. Реализация: **Luna**, интеграция и проверки — основной агент. Контракты и критерии — [PLAN.md](PLAN.md).

## Реализация

| ID | Status | Результат |
|---|---|---|
| F01 | Done | Минимальные IPv4/IPv6 PREROUTING-модули; per-namespace context; lifecycle, lazy-init lock, errno/logs и provider audits |
| F02 | Done | Детерминированная all-tag/model matrix: immutable refs, полные SDK input identities, явные unsupported outcomes |
| F03 | Done | Pinned per-build descriptors, фиксированное окружение и полный ключ сборки через existing helpers |
| F04 | Done | Scheduled/manual refresh -> compare current main -> commit только matrix -> dispatch точного commit SHA |
| F05 | Done | Unique-key planner, изолированные serial builds в bounded shards, archives-only cache и проверенный release reuse |
| F06 | Done | Exact-byte dedup, self-contained manifest/matrix/checksums/details notes и автоматический draft/upload/verify/publish workflow |
| F07 | Done | Exact model/full-release selection, trusted manifest/artifact checks и unavailable/fallback; внешний keen-pbr отдельно |
| F08 | WIP | Локальные проверки завершены; initial remote backfill/release остаётся |
| F08.1 | Done | 36 regressions, actionlint, shellcheck, runtime-safety; native MIPS/ARM64 и clean-kernel reproducibility |
| F08.2 | Done | Native snapshot assembly, exact runtime selections, повторное использование настоящих .ko и operator README |
| F08.3 | ToDo | Удалённая сборка всех accepted keys, полный первый release и повторный workflow с reuse |
| CI01 | Done | ShellCheck 0.9.0: явные условия вместо SC2015; scoped annotation для trap cleanup SC2317/SC2329. Полный check прошёл в pinned container |
| CI02 | Done | Persistent safe.directory для точного GITHUB_WORKSPACE и fail-fast checked SHA; ownership failure воспроизведён, полный planner/36 tests прошли в pinned container |
| HW01 | ToDo | Проверки на настоящих роутерах и evidence-based status promotion |

## Доказательства

- [kernel-matrix.json](kernel-matrix.json): **123 SDK-тега**, **4 976 поддерживаемых model/tag пар**, **3 475 уникальных SDK input keys**, **8 unsupported KAP-пар**. Разрешены **59 kernel commits**, **17 upstream Linux versions**.
- Все **36 source tests** проходят; **actionlint 1.7.12**, **shellcheck**, **runtime-safety** и **git diff --check** проходят.
- SDK **4.03.C.3.0-2 / KN-1810**, **5.00.C.12.0-0 / KN-1810** и **5.00.C.12.0-0 / KN-1812** реально собраны в pinned amd64 container; все шесть IPv4/IPv6 модулей прошли ELF/vermagic/version/priority/ABI и provenance audits.
- Повторная KN-1810/4.03 сборка после `make target/linux/clean`: обе .ko, kernel config и Module.symvers **байт-в-байт одинаковы**. Отчёт: `out/validation/reproducibility.json`.
- 4.03/5.00 MIPS имеют одинаковый vermagic, но разные module SHA256; поэтому kernel release/vermagic не используются как доказательство reuse.
- Validation subset: три конфигурации, три SDK-тега, пять поддерживаемых consumers, шесть уникальных .ko. Проверены **10 точных runtime selections** и refusal неизвестного **KN-1910 / 5.00.C.8.0-1**.
- Все три native builds импортированы через prior snapshot index и повторно прошли реальный ELF/audit. Повторный snapshot полностью совпадает по байтам и digest. Отчёт: `out/validation/end-to-end-current/report.json`.
- Downloads-only cache проверен на двух последовательных SDK checkouts от UID 1000 с настоящими локальными Git/tag checks и stand-in compiler: архив сохраняется, .config не переносится. Отчёт: `out/validation/cache-shard-report.json`. Workflow повторяет checkout после установки Git, поскольку начальный slim container получает архив без Git history.

## Что ещё не выполнялось

Первый [GitHub Actions check](https://github.com/maksimkurb/keen-pbr-kmod-keenetic/actions/runs/37511421304/job/112433247264) завершился до tests/build на ShellCheck 0.9.0 (SC2015 и SC2317). Исправление CI01 прошло в следующем удалённом run.

Во [втором run](https://github.com/maksimkurb/keen-pbr-kmod-keenetic/actions/runs/37520590815/job/112465024352) check прошёл, planner создал 3 475 keys/256 shards, затем Git остановил запись SHA с `detected dubious ownership`. Setup теперь постоянно регистрирует только точный GITHUB_WORKSPACE; запись checked SHA больше не маскирует ошибку через echo. В pinned container воспроизведён exit 128 до исправления, после него прошли полный planner и GitHub outputs, ShellCheck 0.9.0, 36 tests и runtime-safety. Проверено, что чужой checkout остаётся запрещённым и ошибка SHA останавливает шаг без outputs. Отчёт: `out/validation/ci-ownership.json`. Повторная удалённая проверка CI02 остаётся в F08.3.

Полный backfill **3 475** build keys, публикация и router hardware tests не выполнялись. Validation snapshot — локальный subset, не полный release. Все новые mappings остаются **experimental**; runtime требует opt-in. Код workflow публикует автоматически только после полного покрытия и всех проверок.

out/ и .cache/ не коммитятся. Изменения внешнего keen-pbr, flash/reference-module matching и угадывание по ближайшему SDK-тегу не входят в этот репозиторий.
