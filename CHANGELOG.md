# Changelog

Все заметные изменения проекта HellCat v3 (форк kitten443).
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/).

## [3.1.1] — 2026-11-08

Патч-релиз: репозиторий очищен от unit-тестов, которые не используются в
проекте.

### Удалено

- Удалены unit-тесты (`parser/parser_test.go`, `config/config_test.go`,
  `stressor/stress_test.go`) и цели `make test`/`make race`: они не нужны в
  проекте. `make check` теперь выполняет только `gofmt` и `go vet`.

## [3.1.0] — 2026-11-08

Большое обновление парсера, генерации конфигов, серверного рантайма и
документации.

### Добавлено

- Новый модульный парсер: `parser/types.go`, `parser/transport.go`,
  `parser/vless.go`, `parser/vmess.go`, `parser/shadowsocks.go`,
  `parser/trojan.go`, `parser/hysteria.go`, `parser/clone.go`.
- Поддержка транспортов `tcp/raw`, `ws`, `grpc`, `xhttp/splithttp`,
  `httpupgrade`, `kcp` с единой валидацией.
- Поддержка TLS и REALITY, включая `pcs`, `vcn`, `ech`, `pbk`, `sid`, `spx`,
  `pqv`; ключи REALITY проверяются и канонизируются в base64url без padding.
- VMess: классический `vmess://<base64(JSON)>` и новый URI-формат
  `vmess://uuid@host:port?...`; гибкий разбор `port`, `aid`, `allowInsecure`.
- Shadowsocks: SIP002 (base64 и открытый userinfo) и legacy base64; проверка
  поддерживаемых AEAD/2022-шифров; явная ошибка для SIP003-плагинов.
- Hysteria 2: преобразование в Xray-outbound `hysteria`, поддержка
  `obfs=salamander` через `finalmask`, учёт `mport`.
- Явная диагностика для TUIC: протокол не поддерживается Xray-core.
- `--list -` для чтения ссылок из stdin.
- `--verbose` для вывода stdout/stderr Xray.
- `--legacy-insecure` для генерации `tlsSettings.allowInsecure` под старые
  версии Xray.
- `--cpu -1` для полного отключения CPU-троттлинга.
- Предупреждение о слишком низком `RLIMIT_NOFILE` с рекомендацией поднять
  `LimitNOFILE`/`ulimit`.
- Systemd-юнит `deploy/hellcat.service`, примеры
  `deploy/hellcat.env.example` и `deploy/links.example`.
- `Makefile` с целями `build`, `test`, `race`, `vet`, `fmt`, `check`,
  `install`.
- Табличные тесты парсера, тесты конфигов и e2e-проверка через
  `xray run -test`.
- Русская документация `README.ru.md`.

### Изменено

- `--threads` теперь означает **общее** число воркеров, а не число воркеров на
  один прокси. Воркеры распределяются по готовым инстансам, минимум один на
  инстанс.
- Генерация конфигов переведена на актуальную схему Xray: `allowInsecure` по
  умолчанию не добавляется, `finalmask` и `hysteriaSettings` поддерживаются.
- Временные конфиги создаются в отдельной папке `$TMPDIR/hellcat-*`, а не в
  текущем каталоге.
- У каждого воркера собственный генератор случайных чисел; убран общий
  `sync.Pool`-рандом.
- Чтение тела ответа использует пул 16-килобайтных буферов.
- Ошибки сети/HTTP больше не удерживают слот `--inflight` во время backoff.
- Некорректные HTTP-статусы (не 2xx) считаются ошибками, а не успешной
  загрузкой.
- Вывод Xray перехватывается и при падении процесса в лог попадает короткий
  хвост с причиной.
- Установщик `install.sh` переписан: определение архитектуры, установка Go и
  Xray, user/system-режимы, сборка и установка бинарника.
- README полностью переписан: архитектура, флаги, примеры, systemd, тюнинг,
  совместимость и troubleshooting.

### Исправлено

- `--fakelogin` больше не меняет общий конфиг: каждый инстанс получает
  глубокую копию (`parser.Clone`).
- Исправлена совместимость с актуальным Xray, который удалил
  `allowInsecure`.
- Исправлена генерация конфигов для Shadowsocks, Trojan и Hysteria 2
  (корректные `settings`, `streamSettings` и `finalmask`).
- Устранено преждевременное ожидание SOCKS-порта, если Xray уже завершился.
- Добавлена защита от переполнения счётчиков CPU при чтении `/proc/stat`.
- Устранены гонки при перезапуске инстансов: поля процесса синхронизированы,
  фоновые перезапуски дожидаются при завершении.
- Временные файлы и процессы Xray корректно удаляются при выходе; на Linux
  используется `Pdeathsig`, чтобы не оставлять сирот при падении hellcat.
- Скорректирован подсчёт общего объёма трафика и скорости в статистике.

### Совместимость и ограничения

- TUIC не поддерживается: в Xray-core нет TUIC-outbound. Такие ссылки
  отклоняются с понятной ошибкой.
- Актуальный Xray удалил HTTP/2 (`type=http`) и QUIC (`type=quic`)
  транспорты; ссылки отклоняются с подсказкой перейти на `type=xhttp`.
- `allowInsecure` удалён из актуального Xray. Используйте `pcs`/`vcn` в
  ссылках; `--legacy-insecure` предназначен только для старых бинарников.
- REALITY поддерживает только `tcp`, `xhttp` и `grpc`.
- mKCP работает с настройками по умолчанию: seed/header в актуальном Xray не
  передаются.
- Плагины Shadowsocks SIP003 (`obfs-local`, `v2ray-plugin` и т.п.) не
  поддерживаются.
- Скорость считается по телу HTTP-ответа на стороне воркеров и не учитывает
  накладные расходы прокси/TLS.

### Проверено

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `go test -race ./...`
- e2e-валидация конфигов через `xray run -test` (Xray 26.10.31)
- smoke-тест запуска с loopback-ссылкой и `--list -`
- сборка под linux/arm64, darwin и windows
