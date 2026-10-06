# Финальный план keen-pbr-kmod

Планирование: **Sol**. Реализация: **Luna**, интеграция и проверки — основной агент. Состояния: ToDo / WIP / Done.

Цель: автоматически собирать минимальное количество модулей для всех опубликованных Keenetic SDK и выбирать артефакт по **точной модели + полному релизу KeeneticOS**.

```text
model + exact OS release
  -> pinned SDK/model configuration
  -> complete build-input key
  -> content-addressed IPv4/IPv6 .ko
```

## Что готово — Done

- Минимальные IPv4/IPv6-модули, per-namespace context, сериализация lazy table registration, errno/logs и аудит provider exports.
- kernel-matrix.json: 123 SDK-тега, 4 976 поддерживаемых tag/model пар, 3 475 полных SDK input identities и 8 явно unsupported KAP-пар; 59 kernel commits, 17 upstream versions.
- Оба workflows: refresh/commit/dispatch и unique-key build/reuse/assembly/publication. Release содержит exact mapping, provenance, уникальные .ko, checksums и details-таблицы.
- Exact runtime selector с проверкой доверенного manifest, SHA256 и kernel release; unknown модели/релизы получают unavailable/fallback.
- 36 host tests, actionlint, shellcheck и runtime-safety прошли. Настоящие MIPS-сборки SDK 4.03/5.00 и ARM64-сборка SDK 5.00 прошли полный аудит.
- Повторная MIPS-сборка после kernel clean дала байт-в-байт одинаковые IPv4/IPv6 .ko, kernel config и Module.symvers.
- Локальный snapshot на трёх настоящих сборках: 10 точных runtime selections, импорт всех шести модулей из prior snapshot и байт-в-байт одинаковый повторный snapshot. SDK 5.00.C.12.0-0/-1 используют один build key.

Реализация автоматизации завершена и проверена локально. Полный initial backfill 3 475 keys, удалённый GitHub workflow/release и hardware verification ещё не выполнялись. Локальный validation snapshot покрывает только явно выбранный subset и не является полным release.

## Итоговые контракты

### Модуль

- Раздельные IPv4/IPv6 .ko; legacy xtables table keenpbr; только PREROUTING; default priority -149, VERSION и table ABI 1 в metadata.
- Автоматический release matrix использует один priority: after-mangle -149. Существующие локальные build-time modes сохраняются в input key, но не умножают автоматическую матрицу и не образуют отдельный экспериментальный этап. Без kernel patches, AUTOLOAD и собственного policy engine.
- Правила исполняет xtables core. Не добавляем собственный разбор skb, routing/conntrack и чтение внутренних полей xt_table.
- Для packet hook используем собственный per-namespace context через nf_hook_ops.priv; операции не разделяют изменяемый priv между namespaces.
- В обоих закреплённых register_table путях указатель таблицы публикуется до регистрации hooks; priv автоматически не заполняется. Сохраняем lifecycle, порядок teardown и полный unwind.
- Обычные ошибки allocation/registration: errno и stage-specific log; userspace получает ошибку загрузки. Универсально перехватить ABI-induced OOPS нельзя.
- Источники экспортируют нужный API, но фактическая конфигурация должна включать IPv4 provider; IPv6 provider необязателен. Проверяем эффективную конфигурацию и built artifacts.

### Build identity и воспроизводимость

Полный ключ включает kernel source commit, SDK tree с recipes/patches/configuration и toolchain download recipes, module sources/VERSION, ABI/priority, effective flags, build/audit scripts и фиксированное окружение. Наблюдаемые SHA256 скачанных архивов, effective kernel config и Module.symvers сохраняются в provenance и входят в snapshot digest.

SDK/OS tag и SDK commit — lookup/provenance. README-only изменение не меняет доказанно те же build inputs. Если зависимости нельзя установить полностью, применяем консервативную identity полного SDK tree с явным ограничением: возможны лишние сборки.

Выбираем и фиксируем MIPS call policy как параметр итоговой сборки; текущее различие sdk/long не превращаем в отдельный экспериментальный pipeline. Изменение policy инвалидирует reuse.

Фиксируем compiler/binutils, sources/headers/generated config, paths, time, build user/host и поддерживаемые Linux 4.9 SOURCE_DATE_EPOCH/KBUILD controls. Воспроизводимость подтверждаем двумя clean builds, а не обещаем по SDK-тегу.

### Matrix и workflows

kernel-matrix.json детерминированно перечисляет все опубликованные теги и модельные конфигурации: exact tag/series/model, immutable peeled SDK/kernel commits, configuration/toolchain identities, support outcome и SDK input identity.

Неизвестные parser/config layouts, архитектуры и kernel families получают явный unsupported outcome либо ошибку discovery; значения не угадываем. Volatile timestamps в semantic JSON отсутствуют.

**Refresh Keenetic SDK Matrix:** scheduled + manual; fetch all tags; сравнение с актуальным main; commit только изменённого kernel-matrix.json. Параллельные writers сериализуются; при изменившемся main regenerate/recompare без force push.

После успешного bot push явно dispatch Build на main с input source_ref=<committed SHA>. Сам workflow_dispatch ref — branch/tag; checkout сборки — точный source_ref. Это обход штатного подавления push-trigger от GITHUB_TOKEN без PAT.

**Build kernel modules:** matrix changes на main, relevant module/build/contract/workflow inputs и manual; refresh также dispatches его явно. Повторный запуск того же snapshot не публикует дубль.

Планировщик сохраняет все model/tag consumers, но строит один раз каждую доказанно одинаковую полную input identity. Один Linux version или одинаковая config file недостаточны.

Каждая concurrent build получает изолированный SDK и per-build pinned descriptor; global single-SDK provenance заменяется per-build/per-artifact данными. SDK .config не разделяется между concurrent jobs.

Bounded shards содержат последовательные builds и не превышают 256 matrix jobs; одновременно работают не более восьми jobs. Actions cache хранит только downloaded archives с последующими SDK checksum/kernel commit checks. Toolchain, .config, staging_dir и kernel build state создаются заново. Durable reuse берётся из release artifacts после проверки полного key, provenance, audit contract и SHA256.

### Release

После аудита deduplicate реальные байты независимо для IPv4/IPv6 по точному SHA256; имена family/hash. Candidate fingerprints не являются обязательным этапом выпуска или основанием пропускать недоказанную сборку.

Каждый release — self-contained immutable snapshot:

- Все уникальные audited .ko.
- Точная committed kernel-matrix.json.
- manifest.json: exact release/model -> per-family file/SHA256/build key/provenance/status.
- SHA256SUMS для модулей и обоих JSON.

Snapshot tag использует digest matrix + complete module/build inputs и не зависит только от module VERSION. Предыдущий semver workflow адаптируется в этот путь; параллельный legacy publisher не сохраняем.

Перед завершением реализации проверяем targeted regressions, clean-build reproducibility и cross-SDK сборки F08. В рабочем workflow публикация автоматическая: source/runtime checks, успешные сборки всех принятых input keys (включая initial backfill), полное покрытие и audited snapshot являются обязательными gates. Затем создаётся draft, проверяются все uploaded assets/checksums и release публикуется. Failed builds блокируют публикацию и не получают success links; явно unsupported случаи видны с причинами. В текущей локальной реализации GitHub workflow/release удалённо не запускаем.

Notes: details по SDK series, таблица Model | SDK series | полные SDK versions | IPv4 | IPv6 | Status. Версии с одинаковыми mappings объединяются; одинаковые файлы имеют одинаковые ссылки на assets текущего release.

До публикации проверяем лимит 1000 assets и реальный размер notes. Превышение asset limit — явная ошибка и предложение разделить releases по series, без скрытого удаления файлов/замены .ko архивом. Полные notes attachment добавляем только при необходимости.

### Runtime selection и последующая интеграция

Перед загрузкой ndmc show version даёт hw_id и полный release. Их exact mapping выбирает SDK/model build key и per-family artifact; проверяем скачанные байты по trusted manifest SHA256. uname-r — sanity check; BSP discriminator добавляется только при подтверждённой необходимости.

Unknown exact release/model, absent SDK/config/artifact или integrity failure -> custom unavailable и fallback custom -> raw -> mangle. IPv6 отсутствие, подтверждённое config, явно отмечается как unsupported; отсутствие ожидаемого файла — ошибка.

Никаких nearest tags, broad series/ranges, угадывания по архитектуре или trial loading. Для отсутствующего SDK допустима только explicit authoritative release/config mapping или подтверждённый alias. Например, на момент аудита 5.00.C.8.0-1 отсутствовал среди SDK tags и не сопоставляется автоматически с 5.00.C.12.*.

Flash reads, reference-module hashes и hardware confirmation не нужны для SDK-derived selection. Artifact integrity и hardware status — разные проверки. Сохраняем experimental opt-in; compile/load success не повышает статус до verified.

Sidecar может быть cache, но не доказательством происхождения; не принимаем произвольный файл через запись текущей модели в marker. Уже загруженный foreign module нельзя подтвердить хешем найденного позднее файла.

Standalone release и selection contract реализуются здесь. Изменения внешнего keen-pbr repository — отдельная последующая интеграция, по этому manifest/fallback контракту; не реализуются в текущем шаге.

## Задачи и статусы

| ID | Status | Работа и критерий готовности |
|---|---|---|
| F01 | Done | Минимальный per-namespace hook context; errno/stage logs; teardown/unwind и config-provider audits без изменения PREROUTING contract |
| F02 | Done | All-tag/model generator и schema; immutable refs; deterministic JSON; complete SDK input identities; honest unsupported cases |
| F03 | Done | Per-build descriptor через existing build helpers; complete key с flags/environment; один путь вместо global SDK provenance |
| F04 | Done | Scheduled/manual refresh; main comparison; only-matrix commit; explicit dispatch exact source SHA |
| F05 | Done | Unique-key planner, isolated SDK builds, bounded shards, archives-only cache и validated durable release reuse; matrix/source/manual triggers |
| F06 | Done | Exact-byte asset dedup, final manifest/checksums/details notes и complete-coverage snapshot publication с limit guards |
| F07 | Done | Exact hw_id/full-release runtime lookup и integrity/fallback; standalone CLI/smoke support без изменений внешнего keen-pbr |
| F08 | WIP | Integrated regression + reproducibility validation, initial all-tag backfill, incremental reuse proof и operator docs |
| F08.1 | Done | 36 regressions, linters/runtime-safety, native cross-SDK/cross-architecture builds и clean-kernel reproducibility |
| F08.2 | Done | Native snapshot assembly, prior-release reuse без повторной компиляции, exact selections/refusal и operator README |
| F08.3 | ToDo | Удалённый initial backfill всех 3 475 keys; первый complete release и повторный workflow с reuse |
| HW01 | ToDo | Отдельная проверка на настоящих роутерах и evidence-based status promotion; не gate SDK-derived selection |

Порядок F08: targeted regression/reproducibility/cross-SDK checks, затем initial accepted unique-key backfill, публикация validated snapshot и проверка incremental reuse. F08 объединяет бывшие отдельные тесты, clean-build checks и полный 73-model sweep. Проверяем MIPS/ARM64 на двух SDK revisions; reproducibility subset строим дважды clean. Полный backfill покрывает все accepted unique keys, без повторного обязательного sweep того же SDK.

Regression coverage: tag peeling, deterministic serialization, parser failures, input-key invalidation/reuse, provenance/integrity mismatch, required IPv6, shards, byte dedup и refusal неполного release. Hardware checks выполняются отдельно.

## Доказательства и ссылки

Подробности: README.md, STATUS.md, out/validation/end-to-end-current/report.json, out/validation/reproducibility.json, out/sdk-tag-audit.json и out/xtables-api-audit.json. out/ и .cache/ остаются локальными, не коммитятся.

- [Keenetic SDK: exact release workflow](https://github.com/keenetic/keenetic-sdk#readme).
- [GitHub workflow triggers и GITHUB_TOKEN](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
- [GitHub release quotas](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).
- [Kbuild reproducible builds](https://docs.kernel.org/kbuild/reproducible-builds.html).
- [Linux internal API limits](https://docs.kernel.org/process/stable-api-nonsense.html).
