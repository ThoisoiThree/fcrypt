# Пошаговый выпуск новой версии fcrypt

Этот tutorial описывает полный выпуск: GitHub Release с бинарниками, npm-пакеты,
crates.io и Linux-репозитории. Команды ниже используют версию `0.3.5`; для
следующего релиза замените её на нужную.

## 1. Однократная настройка GitHub

### crates.io

1. Войдите на crates.io и создайте API token, которому разрешена публикация.
   Для самой первой публикации `fcrypt-oqs-sys` и `fcrypt-oqs` токен не
   получится ограничить уже существующими пакетами, потому что пакетов ещё нет.
2. Откройте GitHub: `Settings → Environments → New environment`.
3. Создайте environment с именем `crates-publish`.
4. Добавьте в него secret `CARGO_REGISTRY_TOKEN` со значением токена crates.io.
5. Желательно включить `Required reviewers`. Тогда загрузка в crates.io
   начнётся только после ручного подтверждения.
6. После первого успешного выпуска создайте более узкий токен для уже
   принадлежащих вам crates и замените secret.

Workflow `.github/workflows/crates.yml` публикует пакеты строго по порядку:

1. `fcrypt-oqs-sys`;
2. `fcrypt-oqs`;
3. `fcrypt`.

Он ждёт появления каждой зависимости в индексе crates.io и безопасно пропускает
уже опубликованную версию при повторном запуске.

### npm

1. Создайте GitHub environment `npm-publish` и включите required reviewers.
2. Для каждого из семи npm-пакетов настройте Trusted Publishing:

   - provider: GitHub Actions;
   - repository: `ThoisoiThree/fcrypt`;
   - workflow: `npm.yml`;
   - environment: `npm-publish`;
   - permission: publish.

3. Не добавляйте постоянный `NPM_TOKEN`: workflow использует OIDC.
4. Точный список пакетов и команды восстановления trust-настроек находятся в
   корневом `RELEASE.md`.

### Linux-пакеты и GitHub Pages

Если нужны APT/RPM-репозитории:

1. Включите GitHub Pages с источником GitHub Actions.
2. Добавьте repository secrets:

   - `PACKAGING_GPG_PRIVATE_KEY`;
   - `PACKAGING_GPG_PASSPHRASE`.

3. Подробная настройка описана в `docs/PACKAGE_REPOSITORIES.md`.

## 2. Подготовка версии

Начинайте с актуальной основной ветки и чистого working tree:

```bash
git switch main
git pull --ff-only
git status --short
```

Задайте версию без буквы `v`:

```bash
RELEASE_VERSION=0.3.5
```

Обновите:

- `Cargo.toml`;
- версию пакета `fcrypt` в `Cargo.lock`;
- корневой `package.json`;
- все `npm/packages/*/package.json`;
- версии шести `optionalDependencies` в корневом `package.json`;
- секцию и compare-ссылки в `CHANGELOG.md`.

Пакеты `fcrypt-oqs` и `fcrypt-oqs-sys` не следует повышать вместе с каждым
релизом fcrypt. Их версии меняются только при изменении самих bindings или
закреплённой ревизии liboqs.

Проверьте синхронность метаданных:

```bash
bash packaging/scripts/check-release-version.sh "$RELEASE_VERSION"
```

Скрипт также проверит, что commit liboqs одинаков в build script и metadata
sys-crate.

## 3. Локальные проверки

Выполните все команды из корня репозитория:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo build --release --locked
```

Проверьте состав публикуемых пакетов:

```bash
cargo package --manifest-path vendor/fcrypt-oqs-sys/Cargo.toml --list
cargo package --manifest-path vendor/fcrypt-oqs/Cargo.toml --list
cargo package -p fcrypt --list
npm pack --dry-run
```

При первой публикации новых binding-crates полноценный dry-run зависимых
пакетов может заработать только после появления предыдущего пакета в индексе
crates.io. Workflow учитывает это автоматически.

Убедитесь, что нет случайных артефактов:

```bash
git status --short
git diff --check
```

## 4. Commit и CI

Просмотрите изменения, затем создайте release commit:

```bash
git add Cargo.toml Cargo.lock package.json npm/packages CHANGELOG.md \
  RELEASE.md docs .github/workflows packaging/scripts
git commit -m "Release $RELEASE_VERSION"
git push origin main
```

Не создавайте тег, пока обычный CI для основной ветки не станет зелёным.
Проверить его можно на вкладке Actions или через GitHub CLI:

```bash
gh run list --workflow ci.yml --limit 5
gh run watch RUN_ID
```

## 5. Создание тега

Сверьте release commit и создайте подписанный тег:

```bash
git status --short
bash packaging/scripts/check-release-version.sh "$RELEASE_VERSION"
git tag -s "v$RELEASE_VERSION" -m "fcrypt $RELEASE_VERSION"
git show "v$RELEASE_VERSION" --no-patch --show-signature
git push origin "v$RELEASE_VERSION"
```

Если GPG-подпись тегов не настроена, допустим аннотированный тег:

```bash
git tag -a "v$RELEASE_VERSION" -m "fcrypt $RELEASE_VERSION"
git push origin "v$RELEASE_VERSION"
```

Push тега запускает четыре независимых workflow:

- `release.yml` — шесть GitHub-бинарников и SHA-256;
- `npm.yml` — шесть platform packages, затем основной npm launcher;
- `crates.yml` — три Rust-crate в порядке зависимостей;
- `packages.yml` — подписанные DEB/RPM и обновление APT/RPM-репозиториев.

Подтвердите deployment в environments `npm-publish`, `crates-publish` и
`github-pages`, если для них включены reviewers.

## 6. Наблюдение за выпуском

```bash
gh run list --limit 20
gh run watch RUN_ID
gh release view "v$RELEASE_VERSION"
```

При сбое сначала исправьте причину и используйте `Re-run failed jobs`.
Workflow npm и crates.io идемпотентны: уже опубликованные версии будут
пропущены. Не удаляйте и не передвигайте тег после частичной публикации.

## 7. Проверка результата

### GitHub

```bash
gh release view "v$RELEASE_VERSION" --json url,assets
```

Проверьте наличие бинарника и файла `.sha256` для каждой из шести платформ.

### npm

```bash
npm view "@thoisoithree/fcrypt@$RELEASE_VERSION" version
npm view "@thoisoithree/fcrypt-linux-x64@$RELEASE_VERSION" version
```

Дополнительно проверьте установку на текущей платформе во временном каталоге.

### crates.io

```bash
cargo info "fcrypt@$RELEASE_VERSION"
cargo install fcrypt --version "$RELEASE_VERSION" --locked
fcrypt --version
```

Для первого выпуска bindings отдельно проверьте:

```bash
cargo info "fcrypt-oqs@0.11.2"
cargo info "fcrypt-oqs-sys@0.11.2+liboqs-0.15.1"
```

### Контрольная сумма

Скачайте подходящий бинарник и его `.sha256`, затем выполните:

```bash
sha256sum --check fcrypt-linux-x64.sha256
```

На macOS используйте `shasum -a 256 -c <file>.sha256`.

## 8. Ручная публикация crates.io

Используйте этот путь только если workflow недоступен. Вводите токен через
`cargo login`, не помещайте его в командную строку или историю shell:

```bash
cargo login
cargo publish --manifest-path vendor/fcrypt-oqs-sys/Cargo.toml
cargo info "fcrypt-oqs-sys@0.11.2+liboqs-0.15.1"

cargo publish --manifest-path vendor/fcrypt-oqs/Cargo.toml
cargo info "fcrypt-oqs@0.11.2"

cargo publish -p fcrypt --locked
cargo info "fcrypt@$RELEASE_VERSION"
```

Дождитесь появления каждого пакета в индексе перед следующей командой.

## 9. Если опубликована плохая версия

Опубликованную версию нельзя перезаписать тем же номером.

1. Не перемещайте старый тег.
2. Исправьте проблему и выпустите следующий patch-релиз.
3. При необходимости выполните `cargo yank --version X.Y.Z CRATE_NAME`.
4. Для npm пометьте версию через `npm deprecate`.
5. В GitHub Release добавьте предупреждение и ссылку на исправляющую версию.

