# 🔐 RustSSL

Продвинутый инструмент для проверки и анализа SSL/TLS сертификатов, написанный на Rust.

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## ✨ Возможности

- 🔍 **Проверка SSL сертификатов** - получение и анализ сертификатов с любого сервера
- 🔗 **Отображение цепочки сертификатов** - визуализация полной цепочки доверия
- ✅ **Проверка статуса отзыва**
  - OCSP (Online Certificate Status Protocol)
  - CRL (Certificate Revocation List)
- 💾 **Сохранение сертификатов** - экспорт в PEM формат
- 📊 **Множество форматов вывода** - text, json, full
- 🎨 **Цветной вывод** - удобное чтение информации в терминале
- ⚡ **Быстрая работа** - написано на Rust для максимальной производительности

## 📦 Установка

### Из исходников

```bash
git clone https://github.com/yourusername/rustssl.git
cd rustssl
cargo build --release
```

Бинарный файл будет доступен в `target/release/rustssl`

### Установка через cargo

```bash
cargo install --path .
```

## 🚀 Использование

### Базовая проверка сертификата

```bash
rustssl verify -s google.com
```

### Проверка с отображением цепочки сертификатов

```bash
rustssl verify -s github.com --show-chain
```

### Проверка с OCSP

```bash
rustssl verify -s cloudflare.com --check-ocsp
```

### Проверка с CRL

```bash
rustssl verify -s example.com --check-crl
```

### Сохранение сертификата в файл

```bash
rustssl verify -s google.com --save google.pem
```

### Полная проверка с JSON выводом

```bash
rustssl verify -s github.com --show-chain --check-ocsp --check-crl -o json
```

### Проверка на нестандартном порту

```bash
rustssl verify -s example.com -p 8443
```

### Проверка с отключенной валидацией (небезопасно)

```bash
rustssl verify -s self-signed.example.com --insecure
```

## 📋 Опции командной строки

### Команда `verify`

| Опция | Короткая | Описание |
|-------|----------|----------|
| `--server <SERVER>` | `-s` | DNS имя или IP адрес сервера (обязательно) |
| `--port <PORT>` | `-p` | Номер порта (по умолчанию: 443) |
| `--output <FORMAT>` | `-o` | Формат вывода: text, json, full (по умолчанию: text) |
| `--timeout <SECONDS>` | | Таймаут подключения в секундах (по умолчанию: 10) |
| `--insecure` | | Отключить проверку сертификата (небезопасно) |
| `--save <FILE>` | | Сохранить сертификат в файл (формат PEM) |
| `--check-ocsp` | | Проверить статус отзыва через OCSP |
| `--check-crl` | | Проверить статус отзыва через CRL |
| `--show-chain` | | Показать полную цепочку сертификатов |

### Другие команды

```bash
# Показать версию
rustssl version

# Сгенерировать автодополнение для shell
rustssl completion bash > /etc/bash_completion.d/rustssl
rustssl completion zsh > ~/.zsh/completion/_rustssl
rustssl completion fish > ~/.config/fish/completions/rustssl.fish
```

## 📖 Примеры вывода

### Текстовый формат (по умолчанию)

```
╔════════════════════════════════════════╗
║     SSL Certificate Information       ║
╚════════════════════════════════════════╝

Server: google.com
Port: 443

Certificate Details:
  Subject: CN=*.google.com
  Issuer: C=US, O=Google Trust Services, CN=WE2
  Valid From: 2026-03-09 8:36:27.0 +00:00:00
  Valid To: 2026-06-01 8:36:26.0 +00:00:00
  Expires In: 65 (65 days)
  Serial Number: 00b112df9c52575f1a128e17314f9fd3b1
  Version: 3
  Self-signed: No
  Subject Alternative Names:
    • DNS: *.google.com
    • DNS: *.appengine.google.com
    • ... and 127 more
  CA Certificate: No
```

### JSON формат

```json
{
  "server": "google.com",
  "port": 443,
  "certificate_chain": [
    {
      "index": 0,
      "info": {
        "subject": "CN=*.google.com",
        "issuer": "C=US, O=Google Trust Services, CN=WE2",
        "not_before": "2026-03-09 8:36:27.0 +00:00:00",
        "not_after": "2026-06-01 8:36:26.0 +00:00:00",
        "serial": "00b112df9c52575f1a128e17314f9fd3b1",
        "version": 3,
        "is_ca": false,
        "is_self_signed": false,
        "days_remaining": 65
      }
    }
  ],
  "ocsp": null,
  "crl": null,
  "timestamp": "2026-03-27T20:45:28.058929831+00:00"
}
```

## 🏗️ Архитектура

Проект состоит из следующих модулей:

- `main.rs` - точка входа приложения
- `cli.rs` - парсинг аргументов командной строки (clap)
- `verify.rs` - основная логика проверки сертификатов
- `certificate.rs` - парсинг и анализ сертификатов
- `chain.rs` - работа с цепочками сертификатов
- `ocsp.rs` - проверка статуса отзыва через OCSP
- `crl.rs` - проверка статуса отзыва через CRL
- `output.rs` - форматирование вывода
- `completion.rs` - генерация автодополнения для shell

## 🔧 Зависимости

- `clap` - парсинг аргументов командной строки
- `native-tls` - TLS соединения
- `x509-parser` - парсинг X.509 сертификатов
- `reqwest` - HTTP клиент для OCSP/CRL запросов
- `chrono` - работа с датами и временем
- `serde` / `serde_json` - сериализация в JSON
- `colored` - цветной вывод в терминале
- `anyhow` - обработка ошибок

## 🤝 Вклад в проект

Приветствуются любые предложения и pull request'ы! Пожалуйста:

1. Форкните репозиторий
2. Создайте ветку для вашей функции (`git checkout -b feature/amazing-feature`)
3. Закоммитьте изменения (`git commit -m 'Add amazing feature'`)
4. Запушьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📝 TODO

- [ ] Поддержка проверки нескольких серверов одновременно
- [ ] Мониторинг истечения сертификатов
- [ ] Экспорт в другие форматы (XML, YAML)
- [ ] Поддержка клиентских сертификатов
- [ ] Интеграция с системными хранилищами сертификатов
- [ ] Веб-интерфейс для визуализации

## 📄 Лицензия

Этот проект распространяется под лицензией MIT. См. файл [LICENSE](LICENSE) для подробностей.

## 👤 Автор

Ваше имя - [@redbeardster](https://github.com/redbeardster)

## 🙏 Благодарности

- Rust сообществу за отличные библиотеки
- Всем контрибьюторам проекта

---

⭐ Если проект оказался полезным, поставьте звезду на GitHub!
