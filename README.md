# Sentinel-RS

**Автономный безголовый (Headless) агент HIPS / EDR для Linux на базе eBPF LSM и Rust**

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Kernel: eBPF LSM](https://img.shields.io/badge/Kernel-eBPF_LSM_(Linux_5.10%2B)-blue.svg?logo=linux)](https://ebpf.io/)
[![Architecture: Headless HIPS/EDR](https://img.shields.io/badge/Architecture-Headless_EDR-green.svg)](#архитектура)
[![Engine: Deterministic Risk](https://img.shields.io/badge/Engine-Causal_Lineage_%26_Risk-brightgreen.svg)](docs/ARCHITECTURE.md)
[![Memory: < 25-30 MB](https://img.shields.io/badge/RAM-%3C_25--30_MB-success.svg)](docs/PERFORMANCE.md)
[![Tests: 95 Passing](https://img.shields.io/badge/Tests-95_Passed-brightgreen.svg)](docs/TESTING.md)

[English](README.en.md) | **Русский**

---

## 🚀 Быстрый старт: установка и запуск с нуля

Выполните следующие шаги по порядку. Все команды готовы к копированию и вставке в терминал.

### Шаг 1. Установка системных зависимостей и компилятора Rust

Для сборки проекта требуются инструменты компиляции C-кода, библиотеки `libssl`, фаервол `nftables` и свежая версия компилятора **Rust (Cargo)**.

#### Вариант для Debian / Ubuntu / Kali / Astra Linux:
```bash
# 1. Устанавливаем системные сборочные пакеты и nftables
sudo apt update && sudo apt install -y curl build-essential pkg-config libssl-dev nftables git

# 2. Устанавливаем официальный компилятор Rust (rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# 3. Активируем переменные окружения Cargo в текущей сессии
source "$HOME/.cargo/env"
```

#### Вариант для RHEL / CentOS / Rocky Linux / Fedora:
```bash
sudo dnf install -y gcc gcc-c++ make pkgconfig openssl-devel nftables git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

#### Вариант для Arch Linux / Manjaro:
```bash
sudo pacman -Syu --noconfirm base-devel git rustup nftables
rustup default stable
```

> [!TIP]
> Убедитесь, что компилятор доступен, выполнив:
> `cargo --version && rustc --version`

---

### Шаг 2. Клонирование репозитория и сборка бинарников

```bash
# Клонируем исходный код
git clone https://github.com/woifik560/sentinel-rs.git
cd sentinel-rs

# Компилируем оптимизированную релизную версию
cargo build --release
```

После завершения компиляции будут созданы два ключевых исполняемых файла:
* `target/release/sentineld` — фоновый системный демон безопасности.
* `target/release/sntctl` — CLI-утилита управления и мониторинга.

---

### Шаг 3. Запуск агента

Выберите наиболее удобный для вас вариант запуска:

#### Вариант А: Установка в качестве системной службы systemd (Рекомендуется для серверов и десктопов)

```bash
# 1. Копируем бинарники в системный каталог
sudo install -m 0755 target/release/sentineld /usr/local/bin/
sudo install -m 0755 target/release/sntctl /usr/local/bin/

# 2. Создаем рабочие каталоги для сокетов, БД и конфигураций
sudo mkdir -p /etc/sentinel /var/lib/sentinel /run/sentinel

# 3. Копируем конфигурационные файлы и юнит systemd
sudo cp config/config.toml /etc/sentinel/
sudo cp config/rules.toml /etc/sentinel/
sudo cp config/sentineld.service /etc/systemd/system/

# 4. Перезагружаем демоны systemd и запускаем службу
sudo systemctl daemon-reload
sudo systemctl enable --now sentineld.service
```

#### Вариант Б: Прямой запуск в терминале (Для отладки, тестов или в WSL/Docker)

В первом окне терминала запустите демон с правами суперпользователя:
```bash
sudo ./target/release/sentineld --config config/config.toml --rules config/rules.toml
```

Во втором окне терминала (или соседней вкладке) выполняйте команды управления через `sntctl`:
```bash
./target/release/sntctl status
```

---

### Шаг 4. Проверка работоспособности

Убедитесь, что все компоненты функционируют штатно:

```bash
# 1. Запуск комплексной диагностики окружения и ядра
sntctl doctor

# 2. Запрос текущего статуса демона (роль, процессы, память)
sntctl status

# 3. Проверка здоровья всех подсистем (Lineage, Storage, Network, Watchdog)
sntctl health

# 4. Проверка статуса службы systemd (если запускали через Вариант А)
systemctl status sentineld.service
```

---

### Шаг 5. Запуск комплексного теста в реальном окружении

В репозиторий включен автоматический комплекс проверки всех защитных механизмов:
```bash
sudo ./tests/run_live_vm_tests.sh
```

Этот тест проверяет 8 сценариев:
1. `sntctl doctor` и состояние ядра Linux.
2. Инициализацию демона и внедрение правил Netfilter (`inet sentinel`).
3. Разграничение прав (`SO_PEERCRED` RBAC: суперпользователь `RootAdmin` против непривилегированного пользователя `ReadOnly`).
4. Построение дерева предков процессов (Causal Lineage DAG) до PID 1.
5. Заморозку (`SIGSTOP`), разморозку (`SIGCONT`) и ликвидацию процесса с защитой от подмены PID (Anti-PID-Reuse).
6. Защиту нулевого уровня (невозможность убить PID 1 или сам демон).
7. Экстренную сетевую изоляцию хоста (`network isolate`) с сохранением локального loopback (`127.0.0.1`).
8. Моделирование доступа к учетным данным и корректное завершение.

---

## 📋 Повседневное использование CLI (`sntctl`)

Управление агентом происходит полностью через консольную утилиту `sntctl`:

```bash
# -------------------------------------------------------------
# 1. Мониторинг и диагностика
# -------------------------------------------------------------
sntctl status                      # Краткая сводка работы агента
sntctl health                      # Метрики здоровья и watchdog
sntctl doctor                      # Диагностика совместимости ядра и хуков BPF LSM
sntctl monitor                     # Потоковый вывод событий безопасности в реальном времени

# -------------------------------------------------------------
# 2. Управление политиками и защитой
# -------------------------------------------------------------
sntctl protection status           # Статус подсистем защиты
sudo sntctl protection enable      # Включение активной защиты (блокировка угроз)
sudo sntctl protection disable     # Перевод в режим аудита (только логирование)
sudo sntctl policy reload          # Горячая перезагрузка rules.toml без перезапуска

# -------------------------------------------------------------
# 3. Расследование и аудит процессов
# -------------------------------------------------------------
sntctl process inspect <PID>       # Полные атрибуты процесса, хеш SHA-256 и секреты
sntctl process lineage <PID>       # Построение цепочки предков (DAG) до PID 1
sudo sntctl process suspend <PID>  # Экстренная заморозка подозрительного процесса (SIGSTOP)
sudo sntctl unfreeze <PID>         # Возобновление работы процесса (SIGCONT)
sudo sntctl process kill <PID>     # Безопасное уничтожение процесса с верификацией PID

# -------------------------------------------------------------
# 4. Управление инцидентами безопасности
# -------------------------------------------------------------
sntctl incidents list              # Список зарегистрированных инцидентов
sntctl incidents show <ID>         # Детальный отчет инцидента с оценкой риска и причинами

# -------------------------------------------------------------
# 5. Сетевой контроль и изоляция
# -------------------------------------------------------------
sntctl network status              # Текущее состояние фаервола и NFQUEUE
sudo sntctl network isolate        # Полная сетевая изоляция хоста при атаке (кроме loopback)
sudo sntctl network unisolate      # Восстановление стандартной сетевой связности
```

---

## 🧠 Архитектура Sentinel-RS

Проект реализован в виде модульного Rust-воркспейса без сторонних внешних рантаймов (Zero C/Python/LLM):

```
crates/
├── sentinel-common/    # Общие структуры данных, события, IPC-протокол, типы политик
├── sentinel-ebpf/      # Ядерные eBPF-программы, BPF LSM хуки, BPF-карты и RingBuffer
├── sentineld/          # Корневой фоновый демон безопасности (HIPS/EDR Engine)
│   ├── src/collector/  # Сбор и нормализация событий ядра
│   ├── src/lineage/    # Граф причинно-следственных связей процессов (DAG)
│   ├── src/behavior/   # Детектирование подозрительного поведения
│   ├── src/risk/       # Детерминированный движок оценки риска и затухания
│   ├── src/policy/     # 6-этапный движок автономных политик
│   ├── src/response/   # Исполнение мер реагирования (Kill, Suspend, NetBlock)
│   ├── src/incidents/  # Управление жизненным циклом инцидентов и корреляция
│   ├── src/storage/    # Асинхронное хранилище SQLite в режиме WAL
│   ├── src/health/     # Мониторинг здоровья подсистем и Watchdog (sd_notify)
│   └── src/ipc/        # SO_PEERCRED RBAC IPC-сервер
└── sntctl/             # Консольная утилита управления агентом (CLI)
```

### Ключевые защитные механизмы

1. **BPF LSM & Ядерный контроль**: Ранний перехват операций исполнения файлов (`bprm_check_security`), доступа к файлам и сокетам, предотвращение чтения памяти чужих процессов (`ptrace`, `/proc/<pid>/mem`).
2. **Causal Taint Tracking**: Автоматическое мечение процессов, прочитавших чувствительные данные (`/etc/shadow`, `~/.ssh/id_*`, облачные токены), и распространение статуса через `fork`, пайпы, сокеты AF_UNIX и дескрипторы `SCM_RIGHTS`.
3. **Causal Lineage DAG**: Построение графа зависимостей процессов в реальном времени с защитой от переиспользования PID на основе времени старта процесса.
4. **Детерминированный Risk Engine**: Скользящие окна дедупликации, экспоненциальное затухание риска ($T_{1/2} = 300\text{ с}$) и мультипликаторы многоэтапных атак (матрица MITRE ATT&CK).
5. **6-уровневая иерархия политик**:
   * *Уровень 1 (Safety Invariant)*: Иммунитет для PID 1, PID 2 и самого демона `sentineld`.
   * *Уровень 2 (Protected Resources)*: Защита целостности ядра.
   * *Уровень 3 (Admin Deny)*: Запрещающие списки администратора.
   * *Уровень 4 (Admin Allow)*: Разрешающие списки администратора.
   * *Уровень 5 (Behavior Detection)*: Высокоточные поведенческие правила.
   * *Уровень 6 (Operating Mode Defaults)*: Действия по умолчанию (`AUDIT`, `BALANCED`, `STRICT`).
6. **Автономное реагирование**: Безопасный двухфазный Kill, заморозка Suspend, динамический Netfilter NFQUEUE холдинг с отказоустойчивым `bypass`.
7. **Минимальный оверхед**: Потребление оперативной памяти $< 25\text{--}30\text{ МБ}$, время реакции $< 1\text{ мс}$.

---

## 📚 Дополнительная документация

Полный комплект инженерной документации находится в каталоге [`docs/`](docs/):
* [Архитектурная спецификация](docs/ARCHITECTURE.md)
* [Модель безопасности и RBAC](docs/SECURITY_MODEL.md)
* [Модель угроз и анализ векторов атак](docs/THREAT_MODEL.md)
* [Руководство по развертыванию](docs/INSTALLATION.md)
* [Синтаксис конфигурации и правил](docs/CONFIGURATION.md)
* [Спецификация IPC-протокола](docs/IPC_PROTOCOL.md)
* [Совместимость с версиями ядра eBPF](docs/EBPF_COMPATIBILITY.md)
* [Движок автономных политик (Policy Engine)](docs/POLICY_ENGINE.md)
* [Реагирование на инциденты и расследование](docs/INCIDENT_RESPONSE.md)
* [Диагностика и устранение неполадок](docs/TROUBLESHOOTING.md)
* [Методология тестирования и верификации](docs/TESTING.md)
* [Бюджеты производительности и метрики](docs/PERFORMANCE.md)

---

## ⚖️ Лицензия

Проект распространяется под двойной лицензией **MIT** или **GPL-2.0-only**.
