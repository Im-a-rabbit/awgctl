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
awgctl new [OPTIONS] [NAME]
```

| Опция | Описание |
| --- | --- |
| `--address`, `-a` | Адреса сервера (auto: `10.0.X.0/24`) |
| `--port`, `-p` | Порт (auto: `51820-51900`) |
| `--endpoint`, `-e` | Публичный endpoint (auto: `checkip.amazonaws.com`) |
| `--dns` | DNS-серверы |
| `--mtu` | MTU |

### add — добавление клиента

```
awgctl add [OPTIONS] <SERVER> <CLIENT>
```

| Опция | Описание |
| --- | --- |
| `--address`, `-a` | Адреса (auto: первый свободный в подсети сервера) |
| `--default-gateway`, `-d` | Использовать VPN как шлюз по умолчанию |
| `--dns` | DNS-серверы (переопределяет серверные при экспорте) |
| `--no-dns` | Не наследовать DNS от сервера |
| `--keepalive`, `-k` | Persistent keepalive (секунды) |

### rm — удаление сервера или клиента

```
awgctl rm <SERVER> [CLIENT]
```

| Аргумент | Описание |
| --- | --- |
| `<SERVER>` | Имя сервера |
| `<CLIENT>` | Имя клиента. Если указано, удаляет клиента вместо сервера |

Примеры:

```text
awgctl rm awg0             # удалить сервер awg0 и все его конфигурации
awgctl rm awg0 client1     # удалить клиента client1 из сервера awg0
```

### export — экспорт конфигурации

```
awgctl export [OPTIONS] <SERVER> <CLIENT>
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

### list — список серверов и клиентов

```
awgctl list [OPTIONS] [SERVER]
```

| Аргумент / Опция | Описание |
| --- | --- |
| `[SERVER]` | Имя сервера. Если указано, список клиентов |
| `--verbose`, `-v` | Расширенный вывод |

Примеры:

```text
awgctl list                       # список серверов
awgctl list awg0                  # список клиентов сервера awg0
awgctl list -v                    # серверы с endpoint, DNS, MTU
awgctl list awg0 -v               # клиенты с DNS, gateway, keepalive
```

Вывод:

```text
$ awgctl list
Name  Address      Port   DNS
awg0  10.0.0.1/24  51820  —

$ awgctl list -v
Name  Address      Port   Endpoint     DNS  MTU
awg0  10.0.0.1/24  51820  example.com  —    —

$ awgctl list awg0
Name      awg0
Address   10.0.0.1/24
Port      51820
Endpoint  example.com
DNS       —
MTU       —

Name     Address      DNS      Gateway
client1  10.0.0.2/32  —        No
client2  10.0.0.3/32  Inherit  Yes

$ awgctl list awg0 -v
Name      awg0
Address   10.0.0.1/24
Port      51820
Endpoint  example.com
DNS       —
MTU       —

Name     Address      DNS      Gateway  Keepalive
client1  10.0.0.2/32  —        No       No
client2  10.0.0.3/32  Inherit  Yes      25
```

### completions — генерация автодополнений

```
awgctl completions <SHELL>
```

Поддерживаемые оболочки: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

Пример:

```text
awgctl completions bash > /etc/bash_completion.d/awgctl
awgctl completions fish > ~/.config/fish/completions/awgctl.fish
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

- `set` — изменение конфигурации
- `doctor` — проверка и восстановление конфигурации
