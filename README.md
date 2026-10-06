# Host Security Agent (FIM + Log Security Analyzer)

Host Security Agent — это компактный, высокопроизводительный и автономный агент безопасности, разработанный на языке Go. Проект объединяет два ключевых направления обеспечения безопасности серверов и приложений (DevSecOps):

1. **File Integrity Monitor (FIM)** — модуль контроля целостности критических файлов и конфигураций на основе алгоритма SHA-256.
2. **Log Security Analyzer** — модуль асинхронного потокового анализа логов веб-серверов (Nginx/Apache) для обнаружения сигнатур атак (SQLi, XSS, Path Traversal).

Утилита компилируется в один исполняемый бинарный файл, не требует установки внешних зависимостей, интерпретаторов (Python, Node.js) или системных библиотек, что делает её идеальным решением для встраивания в CI/CD пайплайны и мониторинга серверной инфраструктуры.

---

## Архитектура проекта и описание модулей

Проект организован по общепринятым стандартам разработки на Go (Standard Go Project Layout):

```
security-agent/
├── cmd/
│   └── agent/
│       └── main.go           # Точка входа, парсинг CLI-флагов, координация работы
├── internal/
│   ├── config/
│   │   └── config.go         # Модуль загрузки и валидации конфигурации
│   ├── fim/
│   │   └── checker.go        # Модуль контроля целостности файлов
│   └── logscan/
│       └── analyzer.go       # Модуль анализа логов безопасности
├── config.json               # Файл конфигурации по умолчанию
├── baseline.json             # Эталон контрольных сумм файлов (создаётся при -init)
├── report.json               # Итоговый отчёт сканирования в формате JSON
├── access.log                # Файл логов веб-сервера для сканирования
├── go.mod                    # Описание модуля Go
└── README.md                 # Документация проекта
```

---

## Подробный разбор функций и структуры кода

### 1. Точка входа (`cmd/agent/main.go`)

Файл управляет жизненным циклом приложения, парсит флаги командной строки, вызывает модули проверки и формирует итоговый JSON-отчёт.

* **Структуры данных:**
  * `CombinedReport`: объединяет результаты работы FIM (`FIMResult`) и сканера логов (`LogReport`), а также хранит общий статус проверки (`SECURE` или `ALERT`).

* **Функции:**
  * `main()`: 
    * Обрабатывает CLI-флаги (например, `-config` для пути к конфигу и `-init` для создания эталона).
    * Вызывает `config.LoadConfig()` для чтения настроек.
    * При передаче флага `-init` вызывается `fim.CreateBaseline()` и программа завершает работу.
    * Поочерёдно запускает проверки `fim.CheckIntegrity()` и `logscan.AnalyzeLogs()`.
    * Сериализует сводный отчёт в файл `report.json`.
    * Устанавливает код завершения процесса: `Exit Code 0` при отсутствии нарушений и `Exit Code 1` при наличии угроз или изменений файлов.

---

### 2. Модуль конфигурации (`internal/config/config.go`)

Отвечает за считывание и валидацию параметров работы агента из JSON-файла.

* **Структуры данных:**
  * `Config`: мапит поля `config.json` (список отслеживаемых файлов `fim_files`, путь к эталону `baseline_path`, путь к лог-файлу `log_file`, массив регулярных выражений `attack_signatures` и путь к отчёту `report_path`).

* **Функции:**
  * `LoadConfig(path string) (*Config, error)`: открывает файл конфигурации по указанному пути, выполняет анмаршалинг JSON в структуру `Config` и задаёт дефолтные значения для ненайденных путей.

---

### 3. Модуль FIM — File Integrity Monitor (`internal/fim/checker.go`)

Обеспечивает вычисление SHA-256 хешей, формирование эталонной базы и последующий аудит целостности.

* **Типы и структуры данных:**
  * `Baseline`: псевдоним типа `map[string]string` для хранения пар `"путь_к_файлу": "sha256_хеш"`.
  * `FIMResult`: содержит списки неизмененных (`ok_files`), измененных (`modified_files`) и удаленных (`deleted_files`) файлов, а также флаг `has_alerts`.

* **Функции:**
  * `CalculateHash(filePath string) (string, error)`: открывает файл, высчитывает контрольную сумму SHA-256 с помощью `crypto/sha256` и возвращает ее в виде hex-строки.
  * `CreateBaseline(files []string, baselinePath string) error`: обходит список файлов, вычисляет для каждого хеш с помощью `CalculateHash` и сохраняет карту хешей в файл `baseline.json`.
  * `CheckIntegrity(baselinePath string) (*FIMResult, error)`: читает `baseline.json`, повторно считает хеши для указанных в нём файлов, сравнивает их с эталоном и формирует объект `FIMResult` со статусами файлов.

---

### 4. Модуль Log Security Analyzer (`internal/logscan/analyzer.go`)

Реализует асинхронный/потоковый анализ текстовых лог-файлов веб-серверов.

* **Структуры данных:**
  * `ThreatEvent`: детализирует обнаруженную атаку (номер строки `line_number`, IP-адрес `ip`, совпавшая сигнатура `matched_pattern`, исходная строка `raw_line`).
  * `LogReport`: агрегирует статистику проверки (всего строк `total_lines`, число угроз `threats_count`, распределение атак по IP `threats_by_ip`, список событий `events` и флаг наличия атак `has_alerts`).

* **Функции:**
  * `AnalyzeLogs(logPath string, rawSignatures []string) (*LogReport, error)`: 
    * Компилирует регулярные выражения с флагом `(?i)` (регистронезависимость).
    * Построчно считывает лог через `bufio.Scanner` без полной загрузки файла в оперативную память.
    * При совпадении строки с регулярным выражением извлекает IP-адрес источника, фиксирует инцидент в отчёте и выводит alert в консоль.

---

## Конфигурация (`config.json`)

Файл настроек позволяет гибко задавать список контролируемых файлов и правила детекции:

```json
{
  "fim_files": [
    "config.json",
    "cmd/agent/main.go",
    "internal/fim/checker.go"
  ],
  "baseline_path": "baseline.json",
  "log_file": "access.log",
  "attack_signatures": [
    "(\\=|%3D)('|\"|%27|%22)",
    "(SELECT|INSERT|DELETE|UPDATE|DROP|UNION)",
    "(\\.\\./|\\.\\.\\\\)",
    "(<script>|javascript:)"
  ],
  "report_path": "report.json"
}
```

---

## Быстрый старт и запуск в Linux

### Требования

* **Linux OS** (Ubuntu, Debian, CentOS и др.)
* **Go** версии `1.21` или выше (для сборки)

### 1. Установка Go (если ещё не установлен)

```bash
sudo apt update
sudo apt install -y golang-go
```

Проверьте корректность установки:

```bash
go version
```

### 2. Сборка проекта

Находясь в корневой директории проекта `security-agent`:

```bash
go build -o security-agent ./cmd/agent
```

После выполнения команды появится единый исполняемый файл `security-agent`.

### 3. Пошаговое использование

#### Шаг A. Подготовка тестовых данных

Создайте тестовый файл логов `access.log`:

```bash
cat << 'EOF' > access.log
192.168.1.10 - - [10/Oct/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024
10.0.0.5 - - [10/Oct/2026:12:01:00 +0000] "GET /login?user=' OR 1=1-- HTTP/1.1" 500 512
10.0.0.5 - - [10/Oct/2026:12:02:00 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 403 128
EOF
```

#### Шаг B. Инициализация эталона FIM (Baseline)

Перед первым запуском необходимо сохранить безопасное состояние файлов:

```bash
./security-agent -init
```

Вывод:

```text
Инициализация FIM Baseline...
Эталонный файл baseline.json успешно обновлен!
```

#### Шаг C. Запуск агента сканирования

```bash
./security-agent
```

Пример вывода в консоль:

```text
=== [FIM] Мониторинг целостности файлов ===
[OK] config.json
[OK] cmd/agent/main.go
[OK] internal/fim/checker.go

=== [LOGSCAN] Анализ веб-логов безопасности ===
[ATTACK] Стр.2 | IP: 10.0.0.5 | Сигнатура: (?i)(\=|%3D)('|"|%27|%22)
[ATTACK] Стр.3 | IP: 10.0.0.5 | Сигнатура: (?i)(\.\./|\.\.\\)

Итоговый отчет сохранен в: report.json

===========================================
СТАТУС: ОБНАРУЖЕНЫ УГРОЗЫ ИЛИ ИЗМЕНЕНИЯ!
```

---

## Формат отчёта (`report.json`)

После выполнения сканирования утилита сохраняет машиночитаемый JSON-отчёт:

```json
{
  "fim_result": {
    "ok_files": [
      "cmd/agent/main.go",
      "internal/fim/checker.go"
    ],
    "modified_files": [
      "config.json"
    ],
    "deleted_files": [],
    "has_alerts": true
  },
  "log_report": {
    "total_lines": 3,
    "threats_count": 2,
    "threats_by_ip": {
      "10.0.0.5": 2
    },
    "events": [
      {
        "line_number": 2,
        "ip": "10.0.0.5",
        "matched_pattern": "(?i)(\\=|%3D)('|\"|%27|%22)",
        "raw_line": "10.0.0.5 - - [10/Oct/2026:12:01:00 +0000] \"GET /login?user=' OR 1=1-- HTTP/1.1\" 500 512"
      }
    ],
    "has_alerts": true
  },
  "status": "ALERT"
}
```

---

## Пример интеграции в GitHub Actions CI/CD

Файл `.github/workflows/security.yml`:

```yaml
name: DevSecOps Host Security Audit

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Чтение исходного кода
        uses: actions/checkout@v3

      - name: Установка Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Сборка Security Agent
        run: go build -o security-agent ./cmd/agent

      - name: Запуск сканера безопасности
        run: ./security-agent
```

---

## Лицензия и статус проекта

Проект разработан в рамках прохождения производственной практики по направлению DevSecOps на языке Go.