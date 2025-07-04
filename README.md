# Инструкция по установке и запуску сканера

## 1. Обновление системы и установка зависимостей

```bash
apt update && apt upgrade -y
apt install -y masscan nmap curl net-tools python3-pip unzip screen sudo pip
```

## 2. Подготовка директории для сканера

```bash
mkdir z
chmod -R +x z
cd z
```

## 3. Установка nuclei

```bash
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.4.7/nuclei_3.4.7_linux_amd64.zip
unzip nuclei_3.4.7_linux_amd64.zip
chmod +x nuclei
sudo mv nuclei /usr/local/bin/
nuclei -version
rm -rf nuclei_3.4.7_linux_amd64.zip
```

## 4. Проверка установки инструментов

```bash
which masscan
which nmap
which nuclei
```

## 5. Добавление файлов сканера

Скопируйте в папку `z` следующие файлы (или скачайте их из репозитория):

- `play.sh`
- `scan.py`
- `citrix_port.txt`
- `web_stats.py`
- Папку `tech/` с нужными YAML-шаблонами (например, `CVE-2019-19781.yaml`, `CVE-2025-5777.yaml`, `CVE-2023-3519.yaml`)

## 6. Установка Python-зависимостей

```bash
pip3 install flask
```

## 7. Установка прав на запуск

```bash
chmod -R +x z
```

## 8. Запуск веб-статистики в screen

```bash
screen -S web
# Следующая команда запомниться как скрин и будет рабоать в фоне 
python3 web_stats.py --host 0.0.0.0
# Для выхода из screen нажмите Ctrl+A, затем D
screen -R web
# Cнова открыть
```

Можно посмотреть список screen-сессий:
```bash
screen -ls
```

## 9. Запуск задач сканирования

Примеры команд (запускать из папки `z`):

```bash
./play.sh start w1 --ips 145.95.0.1/12 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json

./play.sh start w2 --ips 145.95.0.1/16 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json

./play.sh start w3 --ips 145.100.0.1/12 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json
```

## 10. Управление задачами

```bash
./play.sh status w3    # Проверить статус задачи w3
./play.sh list         # Показать список всех задач
./play.sh stop w3      # Остановить задачу w3
```

## 11. Просмотр веб-статистики

Откройте браузер и перейдите по адресу:
```
http://<IP_СЕРВЕРА>:5000
```

---

**Примечания:**
- Для работы сканера нужны права sudo для masscan!
- Для корректной работы статистики нужен файл `targets.json`, который должен создаваться автоматически (если вы внесли изменения в `scan.py`).
- YAML-шаблоны nuclei кладите в папку `tech/`.
- Не запускайте Flask в debug-режиме на публичных серверах без защиты.s
