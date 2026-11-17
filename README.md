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

## О проекте (Версия 0.2.1)

**Sentinel-RS** — это высокопроизводительный, полностью автономный безголовый (Headless) агент класса **HIPS** (Host Intrusion Prevention System) и **EDR** (Endpoint Detection and Response) для операционных систем Linux (поддерживаются как серверные инсталляции, так и десктопные рабочие станции).

Агент спроектирован для работы в фоновом режиме в виде системного сервиса `systemd` (`sentineld`) под управлением CLI-утилиты `sntctl`. В проекте **полностью отсутствуют графические зависимости** (нет X11, Wayland, Slint, интерактивных графических диалогов и графической аутентификации). Все решения по предотвращению, блокировке и сдерживанию угроз принимаются **детерминированно и автономно** без необходимости ручного подтверждения человеком.

---

## Ключевые возможности

1. **Ядерный уровень контроля (eBPF & BPF LSM)**:
   - Перехват системных событий до их исполнения через хуки BPF LSM (`bprm_check_security`, `file_open`, `file_permission`, `mmap_file`, `ptrace_access_check`, `unix_may_send`, `socket_connect`).
   - Использование ядерных хранилищ `task_storage`, `sk_storage` и BPF Ring Buffer с защитой от насыщения памяти.
   - Детектирование бесфайлового исполнения (`memfd_create`, анонимный `PROT_EXEC`) и защита от чтения чужой памяти процессов (`ptrace`, `/proc/<pid>/mem`, `process_vm_readv`).

2. **Сквозное отслеживание потока данных (Taint Tracking)**:
   - Автоматическая пометка процессов как «зараженных» (Tainted) при доступе к критическим секретам (`/etc/shadow`, `~/.ssh/id_*`, токенам облачных провайдеров, хранилищам паролей).
   - Распространение статуса заражения через `fork`/`clone`, анонимные пайпы, FIFO, дескрипторы `SCM_RIGHTS` и сокеты AF_UNIX.
   - Предотвращение «отмывания» taint через фоновые брокеры.

3. **Causal Process Lineage DAG**:
   - Построение графа причинно-следственных связей процессов в пространстве пользователя.
   - Отслеживание полных цепочек предков (`ancestor_chain`) до PID 1.
   - Гарантированная защита от переиспользования идентификаторов процессов (PID reuse) на основе времени старта из `/proc/<pid>/stat`.

4. **Детерминированный Risk Engine**:
   - Расчет нормализованной оценки риска ($0 \le S \le 100$).
   - Дедупликация свидетельств в скользящих временных окнах.
   - Экспоненциальное затухание риска со временем полураспада $T_{1/2} = 300\text{ сек}$.
   - Мультипликаторы многоэтапных атак (комбинирование техник по матрице MITRE ATT&CK дает коэффициент до $1.6\times$).

5. **Шестиуровневая иерархия политик (Policy Engine)**:
   1. *Уровень 1 (Safety Invariant)*: Абсолютный иммунитет для PID 1, PID 2 и демона `sentineld`.
   2. *Уровень 2 (Protected Resources)*: Защита целостности ядра и критических системных путей.
   3. *Уровень 3 (Admin Deny)*: Явные запрещающие правила администратора.
   4. *Уровень 4 (Admin Allow)*: Явные разрешающие списки администратора.
   5. *Уровень 5 (Behavior Detection)*: Срабатывания высокоточных поведенческих правил.
   6. *Уровень 6 (Operating Mode Defaults)*: Действия по умолчанию для режимов `AUDIT`, `BALANCED`, `STRICT` и `CUSTOM`.

6. **Автономный Response Engine**:
   - Двухфазное безопасное завершение вредоносных процессов (`SIGSTOP` $\rightarrow$ проверка `/proc/<pid>/stat` $\rightarrow$ `SIGTERM` $\rightarrow$ `SIGKILL`).
   - Приостановка процессов для криминалистического анализа.
   - Динамическая сетевая блокировка IP и аварийная изоляция хоста через `nftables` с сохранением локального loopback и сокетов управления.

7. **Безопасный CLI & IPC**:
   - Управление исключительно через консольную утилиту `sntctl`.
   - Авторизация на уровне ядра через `SO_PEERCRED` над сокетами `/run/sentinel/sentinel.sock` (RBAC: `RootAdmin`, `Operator`, `ReadOnly`).

8. **Минимальное потребление ресурсов**:
   - 100% чистый Rust (Zero C/Python рантаймов, Zero LLM).
   - Потребление оперативной памяти: **$< 25\text{--}30\text{ МБ}$ RSS**.
   - Время принятия решений: **$< 1\text{ мс}$**.

---

## Архитектура рабочего пространства

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

---

## Быстрый старт

### Требования к системе
- Ядро Linux $\ge 5.10$ (рекомендуется $\ge 6.1$) с включенным BPF LSM (`lsm=...,bpf`).
- Установленные пакеты: `libelf`, `nftables`, `sqlite3`.

### Сборка из исходников
```bash
git clone https://github.com/woifik560/sentinel-rs.git
cd sentinel-rs

# Сборка релизных бинарников
cargo build --release
```

### Установка и запуск службы
```bash
# Установка бинарников и конфигураций
sudo install -m 0755 target/release/sentineld /usr/local/bin/
sudo install -m 0755 target/release/sntctl /usr/local/bin/
sudo mkdir -p /etc/sentinel /var/lib/sentinel /run/sentinel
sudo cp config/config.toml /etc/sentinel/
sudo cp config/rules.toml /etc/sentinel/
sudo cp config/sentineld.service /etc/systemd/system/

# Запуск службы systemd
sudo systemctl daemon-reload
sudo systemctl enable --now sentineld.service
```

### Проверка работоспособности
```bash
# Диагностика окружения
sudo sntctl doctor

# Просмотр статуса агента
sntctl status

# Просмотр метрик здоровья подсистем
sntctl health
```

---

## Примеры использования CLI (`sntctl`)

```bash
# Просмотр статуса защиты
sntctl protection status

# Потоковый просмотр событий безопасности в реальном времени
sntctl events tail

# Вывод списка зарегистрированных инцидентов
sntctl incidents list

# Детальный просмотр инцидента
sntctl incidents show <INCIDENT_ID>

# Инспекция процесса и построение цепочки его предков
sntctl process inspect <PID>
sntctl process lineage <PID>

# Горячая перезагрузка правил без остановки демона
sudo sntctl policy reload

# Аварийная сетевая изоляция хоста при атаке
sudo sntctl network isolate

# Снятие сетевой изоляции
sudo sntctl network unisolate
```

---

## Документация

Полная техническая документация доступна в каталоге [`docs/`](docs/):
- [Архитектурная спецификация](docs/ARCHITECTURE.md)
- [Модель безопасности и RBAC](docs/SECURITY_MODEL.md)
- [Модель угроз и анализ атак](docs/THREAT_MODEL.md)
- [Руководство по установке и настройке](docs/INSTALLATION.md)
- [Конфигурация и синтаксис правил](docs/CONFIGURATION.md)
- [Спецификация протокола IPC](docs/IPC_PROTOCOL.md)
- [Совместимость с версиями ядра eBPF](docs/EBPF_COMPATIBILITY.md)
- [Движок автономных политик (Policy Engine)](docs/POLICY_ENGINE.md)
- [Реагирование на инциденты и расследование](docs/INCIDENT_RESPONSE.md)
- [Диагностика и устранение неполадок](docs/TROUBLESHOOTING.md)
- [Методология тестирования и верификации](docs/TESTING.md)
- [Бюджеты производительности и метрики](docs/PERFORMANCE.md)

---

## Лицензия

Проект распространяется под лицензией MIT.
