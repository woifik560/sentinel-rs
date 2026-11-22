# Sentinel-RS

Автономный headless-агент HIPS / EDR и хостовый фаервол для Linux на базе eBPF LSM и Rust.

Реализованные возможности:
* Ядерный сбор событий исполнения, файловых операций и сетевой активности (eBPF).
* Построение графа причинно-следственных связей процессов (Lineage DAG) с защитой от PID reuse через `pidfd`.
* Отслеживание распространения чувствительных данных (Taint Tracking: SSH-ключи, shadow, cloud tokens) через fork, пайпы и сокеты.
* Детерминированная оценка рисков (Risk Engine) на базе весов эвристик и порогов MITRE ATT&CK.
* Сетевой контроль и экстренная изоляция хоста (`nftables` таблица `inet sentinel`) с защитным таймером Anti-Lockout.
* Двухфазное реагирование на угрозы (безопасный `kill`, заморозка `suspend`, разморозка `unfreeze`).
* Локальный IPC-сервер с разграничением доступа на базе `SO_PEERCRED` (root/privileged vs read-only).
* Локальное хранилище событий и инцидентов на базе SQLite в режиме WAL.

---

## Сборка и установка

### 1. Системные зависимости

* **Debian / Ubuntu / Kali / Astra Linux:**
  ```bash
  sudo apt update && sudo apt install -y curl build-essential pkg-config libssl-dev nftables git
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  ```

* **RHEL / CentOS / Rocky Linux / Fedora:**
  ```bash
  sudo dnf install -y gcc gcc-c++ make pkgconfig openssl-devel nftables git curl
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  ```

* **Arch Linux / Manjaro:**
  ```bash
  sudo pacman -Syu --noconfirm base-devel git rustup nftables
  rustup default stable
  ```

### 2. Сборка

```bash
git clone https://github.com/woifik560/sentinel-rs.git
cd sentinel-rs
cargo build --release
```

Бинарные файлы после сборки:
* `target/release/sentineld` — основной системный демон безопасности (EDR/HIPS).
* `target/release/sentinel-privileged` — изолированный привилегированный хелпер (CAP_KILL, CAP_NET_ADMIN, crash-resilient watchdog).
* `target/release/sntctl` — CLI-утилита управления и мониторинга.

### 3. Автонастройка BPF LSM в ядре (при необходимости)

Если модуль BPF LSM не активен в ядре, утилита может внести необходимые параметры в конфигурацию загрузчика (GRUB / systemd-boot). Для предотвращения случайных изменений требуется интерактивное подтверждение или флаг `--yes`:
```bash
sudo ./target/release/sntctl setup-kernel --yes
```
*(При внесении изменений создается автоматический бэкап и потребуется перезагрузка).*

---

## Запуск

### Вариант 1: Системная служба systemd (Архитектура с разделением привилегий)

Для максимальной безопасности Sentinel-RS использует модель с разделением привилегий: основной демон `sentineld` работает с ограниченными привилегиями, делегируя операции изменения фаервола и сигналов защищенному хелперу `sentinel-privileged`.

```bash
# Установка бинарников в систему
sudo install -m 0755 target/release/sentineld /usr/local/bin/
sudo install -m 0755 target/release/sentinel-privileged /usr/local/bin/
sudo install -m 0755 target/release/sntctl /usr/local/bin/

# Создание рабочих каталогов
sudo mkdir -p /etc/sentinel /var/lib/sentinel /run/sentinel
sudo chmod 0750 /run/sentinel

# Копирование конфигураций и systemd-юнитов
sudo cp config/config.toml /etc/sentinel/
sudo cp config/rules.toml /etc/sentinel/
sudo cp config/sentinel-privileged.service /etc/systemd/system/
sudo cp config/sentineld.service /etc/systemd/system/

# Запуск служб
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-privileged.service
sudo systemctl enable --now sentineld.service
```

### Вариант 2: Прямой запуск в терминале

```bash
sudo ./target/release/sentineld --config config/config.toml --rules config/rules.toml
```

Флаги запуска `sentineld`:
* `-c, --config <PATH>` — путь к конфигурации (по умолчанию `/etc/sentinel/config.toml`).
* `-r, --rules <PATH>` — путь к файлу правил (по умолчанию `/etc/sentinel/rules.toml`).
* `--audit-only` — запуск в режиме аудита (только логирование без активной блокировки).
* `-v, --verbose` — включение подробного вывода (DEBUG-уровень).

---

## Управление через CLI (`sntctl`)

### Глобальные параметры

* `--json` — машиночитаемый вывод данных в формате JSON.
* `-s, --socket <PATH>` — путь к Unix-сокету (`/run/sentinel/sentinel.sock` для root или `/run/sentinel/sentinel-ro.sock` для чтения).

---

### Мониторинг и диагностика

```bash
sntctl status
# Сводка работы: статус демона, число отслеживаемых процессов и состояние защиты

sntctl health
# Проверка здоровья подсистем (Lineage, Storage, Network, Watchdog)

sntctl doctor
# Диагностика окружения: ядро, права, наличие BPF LSM и хуков

sntctl diagnostics
# Внутренняя телеметрия и статистика производительности

sntctl monitor
# Потоковый вывод событий безопасности и алертов в реальном времени (Ctrl+C для выхода)
```

---

### Управление защитой

```bash
sntctl protection status
# Текущий статус активной защиты

sudo sntctl protection enable
# Включение активной защиты (блокировка угроз)

sudo sntctl protection disable
# Отключение активной защиты (перевод в режим аудита)
```

---

### Процессы и расследование

```bash
sntctl process inspect <PID>
# Полные атрибуты процесса: хеш исполняемого файла, права, секреты, статус taint

sntctl process lineage <PID>
# Построение дерева предков процесса (DAG) до PID 1 с защитой от PID reuse

sudo sntctl process suspend <PID>
# Заморозка процесса (SIGSTOP через pidfd)

sudo sntctl unfreeze <PID>
# Разморозка ранее приостановленного процесса (SIGCONT)

sudo sntctl process kill <PID> [--reason "текст причины"]
# Безопасное завершение процесса с верификацией идентичности через pidfd
```

---

### Сетевой контроль и изоляция

```bash
sntctl network status
# Состояние фаервола, очередей NFQUEUE и правил таблицы inet sentinel

sntctl network blocked
# Список заблокированных или изолированных сетевых направлений

sudo sntctl network isolate [--tier full|restricted|selective] [--timeout <сек>] [--trusted-ssh-ip <IP>]
# Экстренная сетевая изоляция хоста (по умолчанию tier: full, timeout: 300 сек)
# Таймер Anti-Lockout автоматически снимет изоляцию при потере связи

sudo sntctl network confirm-isolation
# Подтверждение изоляции хоста и отключение таймера Anti-Lockout

sudo sntctl network unisolate
# Снятие сетевой изоляции и восстановление сетевой связности

sudo nft flush table inet sentinel
# Аварийный сброс сетевых цепочек Sentinel в ядре
```

---

### Инциденты безопасности

```bash
sntctl incidents list [--limit <N>]
# Список зафиксированных инцидентов (по умолчанию 20)

sntctl incidents show <INCIDENT_ID>
# Полный криминалистический отчет инцидента с оценкой риска и причинами

sntctl incidents export <INCIDENT_ID>
# Экспорт отчета инцидента в JSON

sudo sntctl incidents clear
# Очистка базы инцидентов
```

---

### События безопасности

```bash
sntctl events list [--limit <N>]
# Список последних перехваченных событий (по умолчанию 50)

sntctl events show <EVENT_ID>
# Просмотр деталей события по его идентификатору

sntctl events export [--limit <N>]
# Экспорт событий в JSON (по умолчанию до 1000)
```

---

### Политики, правила и валидация конфигурации

```bash
sntctl policy list
# Список загруженных политик безопасности

sntctl policy validate [--file <PATH>]
# Проверка синтаксиса файла правил (по умолчанию /etc/sentinel/rules.toml)

sudo sntctl policy reload
# Горячая перезагрузка правил rules.toml без перезапуска службы

sntctl rules list
# Список активных эвристических правил детекции поведения и их весов

sntctl rules show <RULE_ID>
# Детали конкретного правила

sntctl config validate [--file <PATH>]
# Проверка синтаксиса файла конфигурации (по умолчанию /etc/sentinel/config.toml)
```

---

### Управление службой (systemd)

```bash
sudo systemctl status sentineld     # Статус службы
sudo systemctl stop sentineld       # Остановка службы
sudo systemctl start sentineld      # Запуск службы
sudo systemctl restart sentineld    # Перезапуск службы
journalctl -u sentineld -f          # Просмотр системного лога в реальном времени
```

---

## Конфигурация

* **`config/config.toml` (`/etc/sentinel/config.toml`)** — параметры демона:
  * `general.mode` — режим (`balanced`, `strict`, `learning`).
  * `general.audit_only` — аудит без блокировок.
  * `socket.path` и `socket.readonly_path` — пути к IPC-сокетам.
  * `targets` — флаги защиты Telegram, браузеров, SSH-ключей, криптовалютных кошельков.
  * `whitelist.binaries` — список доверенных бинарников.
  * `context_rules` — правила разрешенного контекста (доступ SSH/Git к удаленным хостам).

* **`config/rules.toml` (`/etc/sentinel/rules.toml`)** — веса эвристик и пороги риска Risk Engine:
  * `thresholds`: `low_max` (0–39 аудит), `grey_max` (40–74 hold & inspect), `high_min` (75–100 блокировка).
  * Правила: исполнение из памяти (`memfd_create`), чтение секретов не-владельцем, подозрительные интерпретаторы, сетевые аномалии и burst-эксфильтрация.

---

## Тестирование

```bash
# Модульные и интеграционные тесты
cargo test

# Стресс- и SLA-бенчмарки (eval latency <= 1.0ms, decision latency <= 5.0ms)
cargo bench --bench sla_benchmarks

# Комплексный тест в реальном Linux-окружении (eBPF, netfilter, RBAC, DAG, kill/suspend, изоляция)
sudo ./tests/run_live_vm_tests.sh
```

---

## Архитектурная и техническая документация

Подробная проектная и аудиторская документация доступна в каталоге `docs/`:

* [Модель разделения привилегий и безопасность IPC](docs/PRIVILEGE_MODEL.md) (`docs/PRIVILEGE_MODEL.md`)
* [Архитектура безопасности Sentinel-RS](docs/SECURITY_ARCHITECTURE.md) (`docs/SECURITY_ARCHITECTURE.md`)
* [Отказоустойчивость сети и Anti-Lockout Watchdog](docs/NETWORK_FAILSAFE.md) (`docs/NETWORK_FAILSAFE.md`)
* [Отслеживание происхождения данных и Taint Tracking](docs/TAINT_TRACKING.md) (`docs/TAINT_TRACKING.md`)
* [Первичный отчет технического аудита (INITIAL_AUDIT)](docs/audit/INITIAL_AUDIT.md) (`docs/audit/INITIAL_AUDIT.md`)
* [Итоговый отчет технического аудита и верификации (FINAL_AUDIT)](docs/audit/FINAL_AUDIT.md) (`docs/audit/FINAL_AUDIT.md`)
