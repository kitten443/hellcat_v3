# HellCat v3

[English](README.md) · [Русский](README.ru.md) · [Changelog](CHANGELOG.md)

> **Только для авторизованного тестирования.** HellCat создаёт интенсивный
> трафик через прокси-серверы. Используйте его только на своей инфраструктуре
> или при наличии явного письменного разрешения. Вы отвечаете за соблюдение
> закона и правил вашего провайдера.

HellCat — стресс-тестер пропускной способности прокси на Go. Он запускает
несколько процессов [Xray-core](https://github.com/XTLS/Xray-core), каждому
даёт локальный SOCKS5-порт и выполняет множество параллельных HTTP-загрузок
через прокси, чтобы измерить скорость, стабильность и количество ошибок.

Инструмент рассчитан на headless-серверы: без интерфейса и интерактивных
вопросов, с предсказуемым потреблением ресурсов, корректной остановкой и
systemd-юнитом.

---

## Как это работает

```
 ссылки (vless/vmess/ss/trojan/hysteria2)
                    │
                    ▼
            парсер ссылок (parser/)
                    │  один outbound Xray на ссылку
                    ▼
   ┌──────────────────────────────────────┐
   │ Xray #1  SOCKS5 127.0.0.1:port ──────┼──┐
   │ Xray #2  SOCKS5 127.0.0.1:port ──────┼──┼──► воркеры
   │ ...                                  │  │      │
   └──────────────────────────────────────┘  │      ▼
                                             └──► HTTP(S)-цели
                                                  (файлы speedtest или страницы)
```

1. Каждая ссылка превращается в один outbound-конфиг Xray.
2. HellCat пишет временный конфиг с SOCKS5-inbound на случайном локальном
   порту и запускает процесс Xray.
3. Воркеры делают HTTP GET через `socks5h://127.0.0.1:<port>`, читают и
   отбрасывают тело ответа, считая байты, запросы и ошибки.
4. Монитор CPU может добавлять паузу между пачками запросов, чтобы не
   превышать заданный процент загрузки процессора.
5. При выходе воркеры отменяются, процессы Xray получают `SIGTERM`, временные
   конфиги удаляются.

---

## Возможности

- **Протоколы:** VLESS, VMess, Shadowsocks, Trojan, Hysteria 2.
- **Транспорты:** TCP/RAW, WebSocket, gRPC, XHTTP (`xhttp`/`splithttp`),
  HTTPUpgrade, mKCP.
- **Безопасность:** TLS и REALITY, включая современные параметры `pcs`/`vcn`.
- **VMess:** классический `vmess://<base64(JSON)>` и новый формат
  `vmess://uuid@host:port?...`.
- **Shadowsocks:** SIP002 (base64 или открытый userinfo) и старый base64.
- **Hysteria 2:** штатный Xray-outbound `hysteria`; обфускация Salamander
  поддерживается через `finalmask` в Xray 26+.
- **Для серверов:** отдельная временная папка на запуск, очистка старых
  файлов, перехват ошибок Xray, parent-death signal, предупреждение о лимите
  файловых дескрипторов, корректная остановка и systemd-юнит.
- **Безопасная ротация:** `--fakelogin` меняет учётные данные в приватной
  глубокой копии конфига, не затрагивая загруженные ссылки.

---

## Требования

| Компонент | Требование |
|-----------|------------|
| ОС | Linux (x86_64, arm64 и 32-битный ARM поддерживаются установщиком) |
| Go | 1.22+ (только для сборки) |
| Xray | актуальный релиз (рекомендуются сборки 2026+; см. [совместимость](#совместимость-с-xray)) |
| Права | не нужны для установки в домашний каталог; root/sudo — для `/usr/local` и systemd |

Установщик сам скачает Go и Xray, если их нет. Для запуска нужны только
`curl` или `wget` и `unzip`.

---

## Быстрый старт

### 1. Установка

```bash
git clone https://github.com/kitten443/hellcat_v3.git
cd hellcat_v3
sudo ./install.sh
```

Установка без root:

```bash
./install.sh --user
export PATH="$HOME/.local/bin:$PATH"
```

Другие режимы:

```bash
sudo ./install.sh --no-deps      # только собрать и установить hellcat
sudo ./install.sh --no-build     # только Go + Xray
sudo ./install.sh --prefix /opt  # установка в /opt/bin
```

### 2. Ручная сборка (по желанию)

```bash
go mod tidy
make build            # создаст ./hellcat
# или:
go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o hellcat .
```

### 3. Запуск

```bash
# Одна ссылка
hellcat --url 'vless://uuid@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws#node'

# Файл, по одной ссылке на строку
hellcat --list links.txt --instances 20 --threads 200

# Чтение из stdin
cat links.txt | hellcat --list - --stealth

# Короткий замер со своей целью
hellcat --list links.txt --duration 120 --target https://speed.cloudflare.com/__down?bytes=10737418240
```

Статистика выводится каждые 3 секунды:

```text
[hellcat] 🌊 412.7 MB/s | total 24.6 GiB | req 8421 | err 12 | workers 200 | inflight 1834/10000 | cpu 68% | throttle 120ms
```

---

## Обновление со старой версии

Полный список изменений — в [CHANGELOG.md](CHANGELOG.md).

- `--threads` теперь означает **общее число воркеров**, а не число на прокси.
  Уменьшите значение, если раньше использовали большие числа с многими
  инстансами.
- Ссылки TUIC теперь отклоняются с понятной ошибкой, а не создают конфиг
  Xray, который не запускается.
- По умолчанию генерируется актуальная схема Xray. Флаг
  `--legacy-insecure` нужен только для старого бинарника Xray.
- Временные конфиги переехали из рабочего каталога в `$TMPDIR/hellcat-*`;
  старые папки удаляются автоматически.
- Новое: `--list -` (stdin), `--verbose`, `--legacy-insecure` и `--cpu -1`
  (отключить троттлинг).

---

## Поддерживаемые ссылки

| Схема | Транспорты | Безопасность | Примечания |
|-------|------------|--------------|------------|
| `vless://` | tcp/raw, ws, grpc, xhttp, httpupgrade, kcp | none, tls, reality | `flow=xtls-rprx-vision` только с tcp + tls/reality |
| `vmess://` | tcp, ws, grpc, xhttp, httpupgrade, kcp | none, tls, reality | base64 JSON и URI |
| `ss://` | напрямую | — | AEAD и `2022-blake3-*`; SIP003-плагины не поддерживаются |
| `trojan://` | tcp, ws, grpc, xhttp, httpupgrade, kcp | tls (по умолчанию), reality, none | пароль может содержать `:` |
| `hysteria2://`, `hy2://` | Hysteria 2 / QUIC | tls | превращается в Xray `hysteria`; `obfs=salamander` — на Xray 26+ |
| `tuic://` | — | — | **не поддерживается:** в Xray-core нет TUIC-outbound |

Понимаются общие параметры ссылок: `sni`, `host`, `path`, `serviceName`,
`authority`, `mode`, `alpn`, `fp`, `allowInsecure`/`insecure`, `pcs`, `vcn`,
`ech`, `pbk`, `sid`, `spx`, `pqv`, `fm` и `extra` для XHTTP.

---

## Флаги

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `--url` | — | Одна ссылка. |
| `--list` | — | Файл со ссылками; `-` читает stdin. Пустые строки и `#` игнорируются. |
| `--max-proxies` | `100000` | Максимум загружаемых ссылок (жёсткий лимит `100000`). |
| `--instances` | `20` | Количество процессов Xray. Если ссылок меньше, они используются по кругу. |
| `--threads` | `200` | **Общее** число воркеров, распределяется по готовым инстансам. `--insane` удваивает. |
| `--duration` | `0` | Время работы в секундах; `0` — до `Ctrl+C`/`SIGTERM`. |
| `--target` | — | Свой `http(s)` URL вместо встроенного списка целей. |
| `--stealth` | `false` | Обычные веб-страницы с таймаутом 20 с вместо больших загрузок (40 с). |
| `--insane` | `false` | Удвоить число воркеров и использовать burst 6 вместо 3. |
| `--cpu` | `0` | Цель по CPU: `0` — авто (70%, 85% в insane), `-1` — отключить троттлинг, положительное число — процент. |
| `--inflight` | `10000` | Максимум одновременных HTTP-запросов (жёсткий лимит `100000`). |
| `--fakelogin` | `false` | Каждые 1000 запросов на инстанс менять учётные данные и перезапускать его Xray. |
| `--legacy-insecure` | `false` | Добавлять `tlsSettings.allowInsecure`. **Только** для старого Xray. |
| `--verbose` | `false` | Показывать stdout/stderr Xray в терминале вместо короткого хвоста ошибок. |
| `--version` | — | Показать версию сборки. |

`--threads` — это общее число, а не «на прокси». При `--instances 20 --threads
200` каждый готовый инстанс получит 10 воркеров. Если инстансов больше, чем
воркеров, каждому достанется минимум один.

---

## Примеры

**Одна VLESS/REALITY-нода**

```bash
hellcat --url 'vless://uuid@example.com:443?type=tcp&security=reality&pbk=PUBLIC_KEY&sni=cdn.example.com&sid=abcd&fp=chrome&flow=xtls-rprx-vision' \
        --instances 10 --threads 200 --duration 300
```

**Большой список с контролем CPU**

```bash
hellcat --list links.txt --max-proxies 5000 --instances 50 --threads 500 --cpu 75
```

**Аккуратная проверка (страницы, без троттлинга CPU)**

```bash
hellcat --list links.txt --stealth --threads 100 --inflight 2000 --cpu -1
```

**Ротация учётных данных**

```bash
hellcat --list links.txt --fakelogin --duration 600
```

**Старый Xray, который ещё принимает `allowInsecure`**

```bash
hellcat --list links.txt --legacy-insecure
```

---

## Развёртывание на сервере (systemd)

```bash
sudo ./install.sh

sudo mkdir -p /etc/hellcat /var/lib/hellcat
sudo cp deploy/links.example /etc/hellcat/links.txt
sudo cp deploy/hellcat.env.example /etc/hellcat/hellcat.env
sudo cp deploy/hellcat.service /etc/systemd/system/hellcat.service

sudo editor /etc/hellcat/links.txt
sudo editor /etc/hellcat/hellcat.env

sudo chmod 0640 /etc/hellcat/links.txt /etc/hellcat/hellcat.env
sudo systemctl daemon-reload
sudo systemctl enable --now hellcat
journalctl -u hellcat -f
```

В `deploy/hellcat.env.example` задаются дополнительные аргументы:

```ini
HELLCAT_ARGS=--instances 20 --threads 200 --inflight 10000 --cpu 65
```

Юнит выставляет `LimitNOFILE=1048576`, перезапускает процесс при сбое и держит
временные конфиги Xray в приватном `/tmp`. Для продакшена раскомментируйте
блок `User=` и запускайте HellCat от непривилегированного пользователя:
Xray не нужны специальные capabilities.

Остановка:

```bash
sudo systemctl stop hellcat
```

---

## Настройка под сервер

Начинайте осторожно и следите за `cpu`, `inflight`, памятью и числом ошибок.

| Сервер | С чего начать |
|--------|---------------|
| 1–2 vCPU VPS | `--instances 5 --threads 100 --inflight 2000 --cpu 50` |
| 4–8 vCPU | `--instances 20 --threads 300 --inflight 10000 --cpu 65` |
| 16+ vCPU | `--instances 40 --threads 800 --inflight 30000 --cpu 75` |
| Очень большой | увеличивайте `--instances` под число ссылок, `--threads` под CPU, а `--inflight` держите в рамках лимита дескрипторов |

Практические правила:

- Один процесс Xray занимает примерно 20–50 МБ RAM. `--instances 100` может
  потребовать несколько гигабайт.
- Каждый одновременный запрос использует несколько сокетов (воркер ↔ локальный
  SOCKS, outbound Xray, цель). Держите `LimitNOFILE` с запасом выше
  `2 × inflight + instances × 32`.
- `--cpu` throttling работает между пачками запросов, а не внутри передачи.
  Если сервер всё равно перегружен, уменьшайте `--threads`/`--inflight` или
  используйте `CPUQuota` в systemd.
- `--stealth` — для умеренного трафика, обычный режим — для насыщения канала.
- `--target` выбирайте быстрый и близкий к прокси endpoint.
- По умолчанию используется `domainStrategy: UseIP`: Xray резолвит домены
  целей локально. Это предсказуемо для серверов без особых настроек DNS.

При слишком низком мягком `RLIMIT_NOFILE` в лог выводится предупреждение.

---

## Совместимость с Xray

HellCat ориентируется на актуальный Xray-core и учитывает изменения протокола:

- **В актуальных релизах Xray (2026) удалён `tlsSettings.allowInsecure`.** Используйте ссылки с
  `pcs` (SHA-256 сертификата) или `vcn` (проверка по имени) либо
  `--legacy-insecure` только со старым Xray.
- **Транспорты HTTP/2 (`type=http`) и QUIC (`type=quic`) удалены.** Такие
  ссылки отклоняются с понятной ошибкой; переходите на `type=xhttp`.
- **REALITY** поддерживает RAW/TCP, XHTTP и gRPC. Ссылки WS + REALITY
  отклоняются.
- **Hysteria 2** реализована через Xray-протокол `hysteria`. Для Salamander
  нужен `finalmask` из Xray 26+; остальные режимы obfs отклоняются.
- **mKCP** работает с настройками по умолчанию. В Xray 26 конфигуратор больше
  не принимает seed/header, поэтому эти параметры ссылок игнорируются.
- **TUIC** не имеет outbound в Xray и всегда отклоняется.

---

## Диагностика

| Симптом | Причина / решение |
|---------|-------------------|
| `'xray' binary not found in PATH` | Запустите `install.sh` или установите Xray и добавьте его в `PATH`. |
| `no Xray instance could be started` | Проверьте место на диске и права на бинарник Xray. |
| `no SOCKS proxy became ready` | Ссылка несовместима с установленным Xray. Запустите с `--verbose`; в лог выводится хвост ошибки. |
| `The feature "allowInsecure" has been removed` | Добавьте `pcs`/`vcn` в ссылку или используйте `--legacy-insecure` со старым Xray. |
| `vless without TLS or other encryption is prohibited` | Актуальный Xray разрешает `security=none` только для приватных/loopback-адресов. Нужен TLS/REALITY. |
| `HTTP/2 transport ... removed` | Замените `type=http` на `type=xhttp` (или используйте старый Xray). |
| `tuic:// is not supported` | Ожидаемо: конвертируйте ноду или используйте инструмент на базе sing-box. |
| `too many open files` | Поднимите `LimitNOFILE`/`ulimit -n`; уменьшите `--inflight`. |
| CPU постоянно около 100% | Уменьшите `--cpu`, `--threads` или `--inflight`; проверьте, нет ли массы ошибок. |
| Много ошибок, низкая скорость | Проверьте прокси вне HellCat, доступность цели и DNS на сервере. |
| Предупреждения Xray о WebSocket/gRPC | Безопасны; эти транспорты пока работают. |

Логи пишутся в stderr. В systemd смотрите `journalctl -u hellcat -f`.
Временные конфиги создаются в `$TMPDIR/hellcat-*` и удаляются при выходе;
папки старше 24 часов вычищаются при следующем запуске.

---

## Структура проекта

```text
.
├── main.go                 CLI, загрузка списка, валидация флагов, сигналы
├── config/                 генерация и очистка временных конфигов Xray
├── parser/                 парсинг ссылок, валидация и глубокое клонирование
│   ├── parser.go           диспетчер и общие хелперы
│   ├── transport.go        соответствие транспортов/безопасности
│   ├── vless.go            VLESS
│   ├── vmess.go            VMess (JSON + URI)
│   ├── shadowsocks.go      Shadowsocks
│   ├── trojan.go           Trojan
│   ├── hysteria.go         Hysteria 2 + диагностика TUIC
│   └── clone.go            глубокая копия для конфигов инстансов
├── stressor/               жизненный цикл Xray, воркеры, CPU-монитор, статистика
├── deploy/                 systemd-юнит, примеры env и списка ссылок
├── install.sh              установка зависимостей, сборка и установка
└── Makefile                сборка, vet, install
```

---

## Разработка

```bash
make check          # gofmt + go vet
make build
```

---

## Ограничения

- Ссылки TUIC отклоняются (в Xray нет такого outbound).
- Плагины Shadowsocks SIP003 (`obfs-local`, `v2ray-plugin`, ...) не
  поддерживаются.
- Старый `allowInsecure` включается только флагом и только для старого Xray.
- Транспорты HTTP/2 и QUIC отклоняются, так как удалены из актуального Xray.
- Скорость считается по телу HTTP-ответа на стороне Go-воркеров. Она не
  учитывает накладные расходы прокси/TLS и не является измерением канала.
- Большие списки целиком хранятся в памяти; на слабых VPS используйте
  `--max-proxies`.

---

## Лицензия

MIT. См. [LICENSE](LICENSE).
