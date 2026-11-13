# Sentinel-RS

**eBPF Desktop Anti-Stealer & Deterministic Context-Aware Firewall for Linux**

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Kernel: eBPF LSM](https://img.shields.io/badge/Kernel-eBPF_LSM_(Linux_6.x%2B)-blue.svg?logo=linux)](https://ebpf.io/)
[![GUI: Slint](https://img.shields.io/badge/GUI-Slint_UI-blueviolet.svg)](https://slint.dev/)
[![Engine: Deterministic Risk](https://img.shields.io/badge/Engine-Causal_Lineage_%26_Risk-brightgreen.svg)](https://github.com/woifik560/sentinel-rs)
[![Memory: < 30 MB](https://img.shields.io/badge/RAM-%3C_30_MB-success.svg)](#ключевые-возможности)
[![Platform: Debian 13](https://img.shields.io/badge/Platform-Debian_13_Trixie-red.svg?logo=debian)](https://www.debian.org/)

[English](README.en.md) | **Русский**

---

## О проекте (Версия 2.0)

**Sentinel-RS** — это ультралегковесный хостовый фаервол и монитор целостности для Linux Desktop, нацеленный на гарантированное предотвращение работы **инфостилеров** (Infostealers) и несанкционированной эксфильтрации конфиденциальных данных.

В отличие от классических пакетных фильтров (`iptables`, `nftables`, `ufw`), которые не знают происхождения данных, и тяжелых антивирусов с непрозрачными эвристиками или нестабильными LLM, Sentinel-RS сочетает:
1. **Ядерные объектные хранилища (eBPF Object Storage)**:
   - Переход с PID/TGID карт на `BPF_MAP_TYPE_TASK_STORAGE`, `BPF_MAP_TYPE_INODE_STORAGE` и `BPF_MAP_TYPE_SK_STORAGE`. Это исключает утечки памяти и гонки при переиспользовании PID (PID reuse).
   - **Синхронизация taint между потоками (`task->group_leader`)**: taint-состояние привязано к лидеру группы потоков, поэтому чтение секрета одним потоком мгновенно блокирует сетевые сокеты всех остальных потоков этого процесса (Go goroutines, Tokio, Python, Node.js).
2. **Сквозное отслеживание потока данных (Taint Tracking) и защита от отмывания taint (Anti-Laundering)**:
   - Хук `lsm/file_permission` перехватывает перетекание секретов через пайпы (`cat ~/.ssh/id_rsa | curl ...`), FIFO и временные файлы (`/tmp`).
   - Хук `lsm/unix_may_send`: блокирует или распространяет taint при попытке слить секрет через сокеты AF_UNIX незаражённому процессу.
   - Хук `lsm/ptrace_access_check` и защита `/proc/<pid>/environ`: запрещает заражённым процессам считывать чужую память через `process_vm_readv`, ptrace или переменные окружения.
3. **Разделение Fast-Path и Slow-Path с удержанием в NFQUEUE**:
   - *Fast-Path в eBPF*: hot-path проверка в `file_permission` выполняется за `< 5 наносекунд` без аллокаций и локов на чистых регулярных файлах, исключая I/O-просадки при компиляции проектов.
   - *Fast-Path в Netfilter*: правило `ct state established,related accept` пропускает весь гигабитный трафик внутри ядра; в userspace NFQUEUE направляется только первый пакет `ct state new` с меткой `SO_MARK` (`0x5E170001`).
   - *Поддержка UDP/QUIC/DNS и уже открытых сокетов*: перехват через `cgroup/sendmsg4/6` и `lsm/socket_sendmsg` мгновенно блокирует передачу даже в сокеты, открытые до чтения секрета.
4. **Защита от LoLBin-атак (Living off the Land) и TOFU**:
   - Скидка доверия пакету dpkg (`-35`) блокируется, если процесс прочитал секрет (`SECRET_NON_OWNER`).
   - Проверка криптографической целостности бинарников по SHA-256 с кэшированием по `(dev, inode, mtime, ctime)` и мгновенной инвалидацией при записи.
   - Механизм **TOFU (Trust On First Use)** для внешнего софта (`~/.cargo/bin`, Flatpak, AppImage, локальные бинарники): фиксация SHA-256 первого запуска и выявление подмены.
   - Контекстные правила («кто + какой секрет + куда»): легитимный `ssh` с приватным ключом может без промпта подключаться к `github.com:22`, но блокируется при попытке уйти на неизвестный IP/порт.
5. **Предохранитель Never-Freeze Allowlist и защита от DoS**:
   - Жесткий список защиты рабочего стола (PID 1, `systemd*`, `dbus*`, `gnome-shell`, `kwin*`, `sway`, `hyprland`, `pipewire`, `NetworkManager`).
   - **Anti-Spoofing**: валидация только по связке `(dev, inode)`, каноническому пути бинарника и системному UID. Подмена `comm` через `prctl(PR_SET_NAME)` или запуск из `/tmp` тривиально пресекаются.
   - Защита очереди NFQUEUE от DoS-спама (лимит `pending_queue_size = 512`, агрегация дубликатов, `OOMScoreAdjust = -900`).
   - Строгие preflight-проверки ядра: проверка наличия `bpf` в `/sys/kernel/security/lsm` и безопасной версии ядра (Linux 6.1+ для предотвращения CVE-2026-64192).

> **Архитектурный принцип V2.0:** Никаких встроенных нейросетей (LLM) в ядре безопасности! Демон не подвержен галлюцинациям, не требует инструкций AVX2, принимает решения за **< 1 миллисекунды** и потребляет **менее 25–30 МБ оперативной памяти**.

---

## Ключевые возможности

- **eBPF Object Storage & Taint Tracking**:
  - `TASK_STORAGE`: хранит статус Taint и профиль доверия задачи, синхронизируется через `task->group_leader`.
  - `INODE_STORAGE`: отслеживает заражение пайпов, FIFO и файлов.
  - `SK_STORAGE`: удерживает ядерную метку `SO_MARK` на сокете.
  - `lsm/file_permission`: hot-path fast exit (< 5 ns) на чистых файлах; при записи секрета помечает inode, читающий процесс наследует метку.
  - `lsm/unix_may_send` & `lsm/ptrace_access_check`: перекрытие отмывания taint через локальные сокеты и ptrace/память.
- **Taint Hygiene (Гигиена меток)**:
  - Исключение из распространения псевдотерминалов (`/dev/pts/*`), `/dev/null`, системных журналов и сокетов Wayland/X11.
  - Строгая фильтрация секретов: защищаются только приватные ключи (`~/.ssh/id_*`), исключая публичные (`*.pub`), `known_hosts` и `config`.
- **Causal Lineage Graph (DAG предков в памяти)**:
  - Отслеживание полной цепочки порождения процессов (`sched_process_fork` / `exec`) в кольцевом LRU-графе на 4096–8192 узлов.
  - Изоляция интерактивных оболочек (bash/zsh) от заражения родительского терминала.
- **Глубокий анализ контекста запуска**:
  - `lsm/bprm_check_security`: ранняя детекция бесфайлового запуска из оперативной памяти (`memfd_create`) до завершения `execve`.
  - Инспекция скриптов интерпретаторов (`python3`, `bash`, `node`, `perl`).
  - TOFU (Trust On First Use) фиксация SHA-256 для Cargo, Flatpak, AppImage.
- **Детерминированный движок риска (0..100) за < 1 мс**:
  - Математически прозрачные веса правил без «черных ящиков».
  - Пороги: **LOW** (0..39), **GREY** (40..74), **HIGH** (75..100).
- **Безопасный «Freeze & Inspect» через NFQUEUE**:
  - Удержание первого пакета нового соединения (`ct state new`) в очереди Netfilter без `SIGSTOP` и без зависания графической сессии.
  - Принцип **Fail-Closed**: автоматический сброс пакета при таймауте 30 секунд.
  - Грамотное восстановление сети (`clean_nftables_rules`) при остановке службы.
- **Защита IPC через `SO_PEERCRED`**:
  - Управляющие вердикты принимаются только от root или UID текущей активной десктопной сессии.
  - Непривилегированный Slint GUI с санитаризацией входных строк от инъекций.
- **Экстремальная легковесность**:
  - Фоновый демон: **< 25–30 МБ RAM**
  - Десктопный GUI: **< 30 МБ RAM**
  - **100% Rust.** Без Python, Electron или C++ зависимостей.

---

## Архитектура системы

```mermaid
flowchart TD
    subgraph Kernel["ЯДРО LINUX (eBPF LSM, Tracepoints & Netfilter)"]
        LSM_BPRM["lsm/bprm_check_security<br/>(Раннее профилирование & Детект memfd_create)"]
        LSM_FILE["lsm/file_open<br/>(Детект чтения секретов & Запись в TASK_STORAGE)"]
        LSM_PERM["lsm/file_permission<br/>(Отслеживание pipe/FIFO: запись в INODE_STORAGE)"]
        SCHED_FORK["sched_process_fork & exec<br/>(Наследование контекста & Shell Isolation)"]
        
        FAST_PATH{"Fast-Path:<br/>Clean & Trusted?"}
        SLOW_PATH["Slow-Path:<br/>Установка sk->mark = 0x5E170001"]
        NFQUEUE_HOOK["Netfilter / nftables NFQUEUE<br/>(Физическое удержание SYN-пакета)"]
        
        LSM_BPRM --> FAST_PATH
        LSM_FILE --> LSM_PERM
        LSM_PERM --> FAST_PATH
        
        FAST_PATH -->|Да (чистый процесс)| PASS["Прямой пропуск (наносекунды)"]
        FAST_PATH -->|Нет (Tainted / LoLBin)| SLOW_PATH
        SLOW_PATH --> NFQUEUE_HOOK
    end

    subgraph Daemon["ФОНОВЫЙ ДЕМОН (sentineld, root, < 30 MB RAM)"]
        RING_BUF["RingBuffer Consumer"]
        
        subgraph Engine["Детерминированный Движок Безопасности"]
            LINEAGE["Lineage Tracker<br/>(LRU граф 8192 узлов, Shell Isolation, memfd)"]
            DPKG["Dpkg Checker & MD5 Integrity<br/>(Верификация по /var/lib/dpkg/info/*.md5sums)"]
            RISK["Risk Engine (0..100 за < 1 мс)<br/>(LoLBin Hardening: запрет скидки при Taint)"]
            ROUTER{"Verdict Router"}
        end

        NF_MGR["NFQUEUE Hold Orchestrator<br/>(NF_ACCEPT / NF_DROP, Fail-Closed 30s)"]
        SAFETY["Never-Freeze Allowlist<br/>(Защита PID 1, systemd, dbus, wayland)"]
        IPC_SOCK["IPC Server (Unix Socket)<br/>(/run/sentinel/sentinel.sock + SO_PEERCRED)"]

        RING_BUF --> LINEAGE
        LINEAGE --> RISK
        DPKG --> RISK
        RISK --> ROUTER
        
        ROUTER -->|0..39: LOW| ALLOW["Разрешить & Аудит-лог"]
        ROUTER -->|40..74: GREY| NF_MGR
        ROUTER -->|75..100: HIGH| BLOCK["NF_DROP + Опциональный SIGKILL"]
        
        NF_MGR <--> SAFETY
        NF_MGR <--> IPC_SOCK
    end

    subgraph Clients["ПОЛЬЗОВАТЕЛЬСКИЙ СЛОЙ"]
        CLI["Терминал: sentinelctl<br/>(watch, monitor, export JSON)"]
        GUI["Легкий GUI: sentinel-gui (Slint)<br/>(Интерактивный промпт, Breadcrumb, Шкала риска)"]
    end

    Kernel -->|События RingBuffer| Daemon
    Daemon <-->|Вердикты NF_ACCEPT / NF_DROP| Kernel
    Daemon <-->|Безопасный JSON-RPC / IPC| Clients
```

---

## Прозрачная шкала риска (Risk Engine)

Каждое событие оценивается по детерминированной таблице весов (`clamp(0, 100)`):

| Правило | Вес | Описание причины |
|---|:---:|---|
| `FILELESS_MEMFD` | **+50** | Запуск кода напрямую из оперативной памяти (`memfd_create`) |
| `SECRET_NON_OWNER` | **+40** | Доступ к секрету или наследование taint через pipe/файл процессом вне App Scope |
| `UNTRUSTED_BINARY_ORIGIN` | **+25** | Запуск из `/tmp`, `/dev/shm`, `~/Downloads` или отсутствие верификации в `dpkg` |
| `SUSPICIOUS_INTERPRETER` | **+20** | Интерпретатор запущен с inline-кодом (`-c`, `-e`), eval, base64 или получен через pipe |
| `FIRST_SEEN_DESTINATION` | **+15** | Первое подключение процесса к внешнему публичному IP-адресу (вне RFC1918 и loopback) |
| `FAST_EXFIL_BURST` | **+15** | Попытка сетевого подключения в течение <= 5 сек после факта чтения секрета |
| `RAW_IP_CONNECT` | **+10** | Сетевое подключение напрямую по IP без зафиксированного DNS-запроса |
| `TRUSTED_PACKAGE_CONTEXT` | **-35** | Бинарник верифицирован в пакетах `dpkg` с проверкой MD5-хеша и запущен штатно (**НЕ действует при Taint!**) |

### Иерархические правила (LoLBin Mitigation):
1. **Запрет скидки доверия**: Если у процесса активен `SECRET_NON_OWNER` или `TAINTED`, правило `TRUSTED_PACKAGE_CONTEXT` (-35) полностью аннулируется.
2. **Несгораемый порог**: Процесс, прочитавший секрет и выходящий в сеть, всегда получает вердикт минимум **GREY** (балл >= 40), даже если это системный `/usr/bin/curl` или `/usr/bin/git`.

---

## Предохранитель Never-Freeze Allowlist

Для устранения риска зависания пользовательского десктопа в Sentinel-RS внедрен неотключаемый защитный список:
- `PID 1` (init / systemd)
- Системные сервисы: `systemd*`, `dbus-daemon`, `dbus-broker`, `NetworkManager`, `wpa_supplicant`
- Графические композиторы и серверы: `gnome-shell`, `kwin_x11`, `kwin_wayland`, `sway`, `hyprland`, `mutter`, `Xwayland`, `Xorg`
- Медиа-подсистема: `pipewire`, `pipewire-pulse`, `wireplumber`
- Инструменты Sentinel: `sentinel-gui`, `sentinelctl`
- Терминалы разработчика: `gnome-terminal`, `kitty`, `alacritty`, `konsole`, `foot`, `wezterm`, `xterm`

Процессы из этого списка **никогда не замораживаются сигналом `SIGSTOP`**.

---

## План инженерного внедрения (4 Вехи)

- [x] **Веха 1 — «Тихий наблюдатель» (Soak / Audit Mode) + Red-Team Test Suite**:
  - Ядерные хранилища `TASK_STORAGE` + `INODE_STORAGE` + `lsm/file_permission`.
  - Отслеживание утечек через пайпы (`cat secret | curl`) и временные файлы.
  - Набор интеграционных тестов Red-Team (`tests/red_team.rs`).
  - Режим `--audit-only` для сбора логов без блокировок.
- [x] **Веха 2 — Детерминированный App Scoping + Защита от LoLBin**:
  - Иерархические пороги риска и проверка MD5-хешей пакетов Debian.
  - Изоляция интерактивных оболочек shell (bash/zsh) от постоянного таинта.
- [x] **Веха 3 — Интерактивный Enforce через SO_MARK + NFQUEUE**:
  - Маркировка сокетов `sk->mark = 0x5E170001` и удержание в `NFQUEUE`.
  - Консольный и фоновый арбитраж с таймаутом Fail-Closed.
- [x] **Веха 4 — Slint UI и форензика («Freeze & Inspect»)**:
  - Графический интерфейс с отображением дерева предков (Breadcrumb) и причин скоринга.

---

## Управление через CLI (`sentinelctl`)

```bash
# Интерактивный перехват событий в реальном времени (для серверов и SSH)
sentinelctl watch

# TUI-монитор активности процессов и сетевых запросов
sentinelctl monitor

# Разморозить ошибочно заблокированный процесс
sentinelctl unfreeze <TGID>

# Экспорт криминалистического отчета (Forensics / JSON)
sentinelctl export <INCIDENT_ID> --format json

# Управление белым списком
sentinelctl whitelist list
sentinelctl whitelist add /usr/bin/curl
```

---

## Структура проекта (Cargo Workspace)

```text
sentinel-rs/
├── crates/
│   ├── sentinel-common/            # Общая библиотека типов, протоколов и моделей
│   │   ├── events.rs               # eBPF-события: file_permission, bprm_check_security, connect, unix_may_send
│   │   ├── process.rs              # ProcessNode, baseline profile, shell isolation, group_leader
│   │   ├── risk.rs                 # Детерминированный движок риска, LoLBin floor, TOFU, RuleId
│   │   ├── ipc.rs                  # Форматы сообщений Unix IPC (PromptRequest, Verdict)
│   │   ├── incident.rs             # Форматирование криминалистических отчетов
│   │   └── config.rs               # Конфигурация SO_MARK, NFQUEUE, Never-Freeze allowlist, context_rules
│   │
│   ├── sentinel-ebpf/              # eBPF LSM хуки, tracepoints и объектные хранилища
│   │   ├── maps.rs                 # TASK_STORAGE, INODE_STORAGE, SK_STORAGE, group_leader, TaintHygiene
│   │   ├── loader.rs               # Загрузчик программ, preflight-проверки ядра, RingBuffer listener
│   │   └── programs/
│   │       ├── file_open.rs        # lsm/file_open: строго приватные секреты & /proc/*/environ
│   │       ├── file_permission.rs  # lsm/file_permission: hot-path fast exit (< 5 ns) & pipe taint
│   │       ├── bprm_check_security.rs # lsm/bprm_check_security: раннее профилирование & memfd
│   │       ├── unix_may_send.rs    # lsm/unix_may_send: защита от отмывания taint через AF_UNIX
│   │       ├── ptrace_access_check.rs # lsm/ptrace_access_check: запрет snooping памяти clean-процессов
│   │       ├── process_fork.rs     # sched_process_fork: наследование с изоляцией shell и потоками
│   │       ├── process_exec.rs     # sched_process_exec: отслеживание бинарников и вычисление хеша
│   │       ├── socket_connect.rs   # Fast-Path allow или Slow-Path SO_MARK (0x5E170001)
│   │       └── socket_sendmsg.rs   # UDP/QUIC/DNS перехват и блокировка pre-opened сокетов
│   │
│   ├── sentineld/                  # Основной системный демон (Root, RAM < 30 MB)
│   │   ├── main.rs                 # Точка входа, event loop, интеграция NFQUEUE
│   │   ├── preflight.rs            # Строгие preflight-проверки ядра (/sys/kernel/security/lsm, Linux 6.1+)
│   │   ├── lineage.rs              # LRU DAG на 8192 узла с shell isolation и group_leader
│   │   ├── risk_engine.rs          # Расчет риска за < 1 мс, FirstSeenDestination, TOFU
│   │   ├── pkg_check.rs            # Верификация происхождения и SHA-256/MD5 целостности
│   │   ├── sha_cache.rs            # Кэш SHA-256 по (dev, ino, mtime, ctime) с мгновенной инвалидацией
│   │   ├── tofu.rs                 # Trust-On-First-Use база для Cargo, Flatpak, AppImage
│   │   ├── context_policy.rs       # Контекстные правила («кто + какой секрет + куда лезет»)
│   │   ├── verdict_cache.rs        # Кэш решений пользователя с инвалидацией при перезаписи бинарника
│   │   ├── freeze.rs               # NFQUEUE Hold Manager (ct state new), Never-Freeze Safety & DoS защита
│   │   ├── ipc_server.rs           # Unix Domain Socket + SO_PEERCRED
│   │   └── tests/
│   │       └── red_team.rs         # Red-Team сьют атак (многопоточный стилер, UDP/QUIC, AF_UNIX, DoS)
│   │
│   ├── sentinelctl/                # Консольная утилита управления (CLI Triage)
│   └── sentinel-gui/               # Легковесный Desktop UI (Slint, RAM < 30 MB, санитаризация строк)
│
├── config/
│   ├── config.toml                 # SO_MARK, NFQUEUE, Never-Freeze список, DoS лимиты, context_rules
│   ├── rules.toml                  # Веса правил (включая TOFU_TAMPERED_BINARY, IPC_TAINT_LAUNDER)
│   └── sentineld.service           # Systemd unit с минимизацией capabilities и OOMScoreAdjust=-900
└── ТЗ.txt                          # Полное техническое задание проекта
```
