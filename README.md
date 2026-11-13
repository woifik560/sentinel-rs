# 🛡️ Sentinel-RS

**eBPF Desktop Anti-Stealer & Local AI Triage Firewall for Linux**

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Kernel: eBPF LSM](https://img.shields.io/badge/Kernel-eBPF_LSM_(Linux_6.x%2B)-blue.svg?logo=linux)](https://ebpf.io/)
[![GUI: Slint](https://img.shields.io/badge/GUI-Slint_UI-blueviolet.svg)](https://slint.dev/)
[![AI: Qwen 2.5](https://img.shields.io/badge/AI-Qwen_2.5_0.5B_(llama.cpp)-green.svg)](https://huggingface.co/Qwen)
[![License: MIT / GPL-2.0](https://img.shields.io/badge/License-MIT_%2F_GPL--2.0-yellow.svg)](LICENSE)
[![Platform: Debian 13](https://img.shields.io/badge/Platform-Debian_13_Trixie-red.svg?logo=debian)](https://www.debian.org/)

[English](README.en.md) | **Русский**

---

## 📌 О проекте

**Sentinel-RS** — это легковесный гибридный хостовый фаервол и монитор целостности для Linux Desktop, нацеленный на обнаружение и пресечение работы **инфостилеров** (Infostealers) и несанкционированной эксфильтрации персональных данных.

В отличие от классических пакетных фильтров (`iptables`, `nftables`, `ufw`), которые оперируют только IP-адресами и портами без понимания контекста происхождения данных, Sentinel-RS использует механизм **Taint Tracking (отслеживание заражения потоков)** на уровне ядра Linux с помощью **eBPF LSM**.

Когда неавторизованный процесс обращается к чувствительным файлам (сессии Telegram, куки и пароли браузеров, приватные SSH-ключи, криптокошельки), ядро помечает процесс флагом `TAINTED`. При первой же попытке открыть сетевой сокет соединение **мгновенно сбрасывается (`-EPERM`)** без зависания интерфейса, а метаданные передаются в двухуровневый движок анализа: сверхбыстрые статические эвристики и локальная нейросеть (**Qwen 2.5 0.5B/1.5B**) для генерации понятного отчёта безопасности без обращения к облаку.

---

## ✨ Ключевые возможности

- 🔒 **eBPF LSM Taint Tracking & App Scoping**: Контроль доступа к секретам по принципу «Владелец секрета» (Telegram может читать только сессии Telegram, Chrome — только свои куки).
- 🧬 **Taint Inheritance**: Автоматическое распространение метки `TAINTED` на дочерние процессы через хук `sched/sched_process_fork`, предотвращающее обход защиты через порождение подпроцессов.
- 🛑 **Non-Blocking Network Drop**: Возврат `-EPERM` на уровне ядра при попытке выхода в сеть, блокирующий передачу украденных данных без зависания GUI и рабочего стола.
- ⚡ **Двухуровневый движок вердиктов (Tiered Engine)**:
  - **Уровень 1 (Fast Heuristics, 0 мс)**: Мгновенное обнаружение очевидных аномалий (запуск из `/tmp`, скрытых папок, отсутствие TTY) и сверка хэшей SHA-256 бинарников с базой `dpkg`.
  - **Уровень 2 (Локальный ИИ-триаж)**: Подключение компактной модели **Qwen 2.5** через `llama-cpp-rs` для семантического анализа «серой зоны» и генерации человекочитаемых объяснений инцидента.
- 🪶 **Экстремальная легковесность**:
  - Фоновый демон: **< 50 МБ RAM**
  - Десктопный GUI: **< 30 МБ RAM**
  - **Никакого Electron или Python!** Полностью нативный стек на Rust.
- 💻 **Поддержка доступного оборудования**: Скомпилирован без жестких требований к AVX2 (полная поддержка процессоров Intel Sandy Bridge / Ivy Bridge с инструкциями SSE4.2 / AVX-1).
- 🎛️ **Двойной интерфейс**:
  - `sentinelctl` — мощная CLI/TUI утилита для терминала, скриптов и системных администраторов.
  - `sentinel-gui` — дружелюбный нативный интерфейс на Slint UI с карточками угроз и иконкой в трее.

---

## 🏗 Архитектура системы (v1.2)

```mermaid
flowchart TD
    subgraph Kernel["🐧 ЯДРО LINUX (eBPF)"]
        LSM_FILE["lsm/file_open<br/>(App Scoping & Taint Tracking)"]
        FORK["sched/sched_process_fork<br/>(Наследование метки TAINTED)"]
        LSM_NET["lsm/socket_connect<br/>(Сетевой перехват: возврат -EPERM)"]
        MAPS[("eBPF Maps & RingBuffer<br/>(PID Taint Flags & Inode Scopes)")]
        
        LSM_FILE -->|Пометка TAINTED| MAPS
        FORK -->|Наследование метки| MAPS
        MAPS -->|Проверка флага| LSM_NET
    end

    subgraph Daemon["⚙️ ФОНОВЫЙ ДЕМОН (sentineld, root)"]
        RING_BUF["RingBuffer Consumer"]
        
        subgraph TieredEngine["Двухуровневый Движок Вердиктов"]
            L1["Level 1: Fast Heuristics (0 мс)<br/>(Пути /tmp, TTY, SHA-256, dpkg)"]
            L2["Level 2: Local AI Triage<br/>(Qwen 2.5 via llama-cpp-rs)"]
        end
        
        CONFIG["Rule & Whitelist Manager<br/>(/etc/sentinel/config.toml)"]
        IPC_SOCK["Unix Domain Socket<br/>(/run/sentinel.sock)"]

        RING_BUF --> L1
        L1 -->|Очевидная угроза| KILL["Мгновенный SIGKILL / Drop"]
        L1 -->|Серая зона| L2
        CONFIG --> L1
        L1 <--> IPC_SOCK
        L2 <--> IPC_SOCK
    end

    subgraph Clients["🖥️ ПОЛЬЗОВАТЕЛЬСКИЙ СЛОЙ"]
        CLI["Терминал: sentinelctl<br/>(TUI Монитор, Правила, Белый список)"]
        GUI["Легкий GUI: sentinel-gui (Slint)<br/>(Системный трей, Статус-Щит, AI-алерты)"]
    end

    Kernel -->|RingBuffer Events| Daemon
    Daemon <-->|JSON-RPC / IPC| Clients
```

---

## 🎯 Защищаемые цели и App Scoping

Sentinel-RS разграничивает доступ к секретам по модели легитимного владения:

| Категория | Защищаемые пути | Легитимный владелец | Тип пресекаемой угрозы |
|-----------|-----------------|---------------------|------------------------|
| **Мессенджеры** | `~/.local/share/TelegramDesktop/tdata/*` | `Telegram` | Кража активной сессии Telegram |
| **Браузеры** | `~/.config/google-chrome/*/Cookies`<br/>`~/.config/chromium/*/Login Data`<br/>`~/.mozilla/firefox/*.default*/places.sqlite` | Браузеры (`chrome`, `firefox` и др.) | Сессионные куки, сохраненные пароли, история |
| **Системные ключи** | `~/.ssh/*`, `~/.gnupg/*` | `ssh`, `gpg`, `git` | Эксфильтрация приватных ключей |
| **Криптокошельки** | `~/.config/Exodus/*`, `~/.electrum/wallets/*` | Авторизованные клиенты кошельков | Кража seed-фраз и кошельков |

---

## 💻 Управление через CLI (`sentinelctl`)

```bash
# Проверить статус службы и состояние модулей защиты
sentinelctl status

# Запустить TUI-монитор событий в реальном времени
sentinelctl monitor

# Добавить доверенный бинарник в белый список (с расчётом SHA-256)
sentinelctl whitelist add /usr/bin/curl
sentinelctl whitelist list

# Переключение режима работы (strict | balanced | learning)
sentinelctl mode balanced

# Снять сетевые ограничения с ложно помеченного процесса
sentinelctl unfreeze <PID>
```

---

## 🖥️ Графический интерфейс (`sentinel-gui`)

Интерфейс спроектирован на базе **[Slint](https://slint.dev/)** — современного нативного GUI-фреймворка для Rust. Бинарник запускается мгновенно и потребляет менее 30 МБ оперативной памяти.

### Основные вкладки:
1. **«Щит» (Главный экран)**:
   - Большой визуальный индикатор состояния безопасности (Зеленый / Красный щит).
   - Главный тумблер включения/выключения защиты.
   - Понятное текстовое объяснение от локального ИИ, если был пойман подозрительный процесс.
   - Индикатор использования оперативной памяти.
2. **«Что защищать»**:
   - Быстрые переключатели для категорий (Telegram, Браузеры, SSH, Крипта).
3. **«Белый список»**:
   - Карточки доверенных приложений с контролем хэшей исполняемых файлов.
4. **Системный трей**:
   - Быстрая пауза защиты на 15 минут, вызов дашборда и индикация статуса рядом с часами.

---

## ⚙️ Конфигурация (`/etc/sentinel/config.toml`)

```toml
[general]
mode = "balanced"            # strict (параноик) | balanced (базовый) | learning (обучение)
ai_enabled = true
auto_kill_score = 90         # Автоматический SIGKILL при подтверждении эвристиками / ИИ > 90%

[targets]
protect_telegram = true
protect_browsers = true
protect_ssh = true
protect_crypto = true

[whitelist]
binaries = [
    "/usr/bin/apt",
    "/usr/lib/firefox/firefox"
]
```

---

## 🛠 Технологический стек

| Направление | Инструмент | Преимущество |
|-------------|------------|--------------|
| **eBPF Ядро** | [Aya](https://aya-rs.dev/) (Rust) | Безопасная разработка eBPF без C-зависимостей и LLVM clang-плагинов |
| **Фоновый демон** | `tokio`, `clap`, `sha2` (Rust) | Высокопроизводительный асинхронный рантайм, проверка целостности |
| **IPC** | `interprocess` / Unix Domain Sockets | Быстрая коммуникация между root-демоном и GUI без оверхеда сети |
| **ИИ Инференс** | `llama-cpp-rs` (Qwen 2.5) | Быстрый инференс на CPU с инструкциями AVX-1/SSE4.2 |
| **Десктопный GUI** | [Slint UI](https://slint.dev/) (Rust) | Мгновенный запуск, ультранизкое потребление RAM, без Chromium |
| **Системные алерты** | `notify-rust` (D-Bus) | Нативные всплывающие уведомления среды рабочего стола |

---

## 📋 Системные требования

- **ОС**: Linux с ядром **6.x+** (протестировано на Debian 13 Trixie)
- **Параметры ядра**: `CONFIG_DEBUG_INFO_BTF=y`, включенный `eBPF LSM` (`lsm=bpf` в grub cmdline; автонастройка через `.deb`)
- **Процессор**: x86_64 с поддержкой SSE4.2 / AVX (Intel Sandy Bridge 2-го поколения и новее)
- **Оперативная память**: от 4 ГБ (демон с моделью ИИ занимает ~380-450 МБ RAM суммарно)

---

## 🗺 Дорожная карта (Roadmap)

- [x] **Этап 1: Архитектурные спецификации и модель триажа (v1.2)**
  - Фиксация двухуровневой модели (Fast Heuristics + AI Triage).
  - Спецификация App Scoping, наследования Taint через fork и сброса сокета (-EPERM).
- [ ] **Этап 2: Ядро и демон eBPF (Бэкэнд)**
  - Реализация хуков `lsm/file_open` с проверкой владельца секрета.
  - Реализация `sched/sched_process_fork` для передачи флага TAINTED.
  - Реализация `lsm/socket_connect` с сетевым сбросом (`-EPERM`).
- [ ] **Этап 3: IPC и Консольный клиент (`sentinelctl`)**
  - Реализация Unix-сокета `/run/sentinel.sock` с JSON-RPC.
  - Команды `status`, `monitor`, `whitelist`, `mode`, `unfreeze`.
- [ ] **Этап 4: Двухуровневый триаж и интеграция ИИ**
  - Движок эвристик (проверка путей, TTY, хэширование SHA-256).
  - Локальный инференс Qwen 2.5 для формирования разъяснений инцидента.
- [ ] **Этап 5: Минималистичный GUI (`sentinel-gui`) на Slint**
  - Разработка интерфейса из 3 вкладок, карточки инцидентов и системного трея.
- [ ] **Этап 6: Упаковка и стендовое тестирование**
  - Сборка `.deb`-пакета с автоконфигурацией GRUB.
  - Валидация на реальных сценариях стилеров и скриптов эксфильтрации.

---

## 📜 Лицензия

Проект распространяется под двойной лицензией **MIT** и **GPL-2.0** (для eBPF компонентов ядра в соответствии с требованиями ядра Linux). Подробнее см. в файле [LICENSE](LICENSE).
