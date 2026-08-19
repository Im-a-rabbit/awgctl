# awgctl

CLI-утилита для управления серверами и клиентами AmneziaWG.

## Установка

```sh
cargo install --path .
```

## Быстрый старт

```sh
awgctl new                          # создать сервер с авто-конфигурацией
awgctl add awg0 client1             # добавить клиента
awgctl export awg0 client1          # вывести конфиг в stdout
```

## Команды

### new — создание сервера

```
awgctl new [name] [OPTIONS]
```

| Опция | Описание |
| --- | --- |
| `--address`, `-a` | Адреса сервера (auto: `10.0.X.0/24`) |
| `--port`, `-p` | Порт (auto: `51820-51900`) |
| `--endpoint` | Публичный endpoint (auto: `checkip.amazonaws.com`) |
| `--dns` | DNS-серверы |
| `--mtu` | MTU |

### add — добавление клиента

```
awgctl add <server> <client> [OPTIONS]
```

| Опция | Описание |
| --- | --- |
| `--address`, `-a` | Адреса (auto: первый свободный в подсети сервера) |
| `--dns` | DNS-серверы (переопределяет серверные при экспорте) |
| `--no-dns` | Не наследовать DNS от сервера |
| `--default-gateway`, `-d` | Использовать VPN как шлюз по умолчанию |
| `--keepalive`, `-k` | Persistent keepalive (секунды) |

### export — экспорт конфигурации

```
awgctl export <server> <client> [OPTIONS]
```

| Опция | Описание |
| --- | --- |
| `--output`, `-o` | Файл для сохранения |
| `--qr`, `-q` | QR-код вместо текста |

Режимы:

| Результат | Что делать |
| --- | --- |
| stdout | Текстовый конфиг в терминал |
| `-o file` | Текстовый конфиг в файл |
| `-q` | QR-код в терминале (Dense1x2) |
| `-o file -q` | QR-код как SVG в файл |

### rm — удаление сервера или клиента

```
awgctl rm <server> [client]
```

| Аргумент | Описание |
| --- | --- |
| `server` | Имя сервера |
| `client` | Имя клиента. Если указано, удаляет клиента вместо сервера |

Примеры:

```text
awgctl rm awg0             # удалить сервер awg0 и все его конфигурации
awgctl rm awg0 client1     # удалить клиента client1 из сервера awg0
```

### completions — генерация автодополнений

```
awgctl completions <shell>
```

Поддерживаемые оболочки: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

Пример:

```text
awgctl completions bash > /etc/bash_completion.d/awgctl
awgctl completions zsh > ~/.zfunc/_awgctl
```

## Конфигурация

| Директория | Описание |
| --- | --- |
| `/etc/awgctl/` | Метаданные (TOML) |
| `/etc/amnezia/amneziawg/` | Конфигурации AmneziaWG (.conf) |

### Переопределение путей

При сборке:

```sh
AWGCTL_CONF_DIR=/custom/path cargo build
AWG_CONF_DIR=/custom/path cargo build
```

## Планируется

- `list` — список серверов/клиентов
- `set` — изменение конфигурации
- `doctor` — проверка и восстановление конфигурации
