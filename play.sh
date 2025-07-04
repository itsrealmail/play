#!/bin/bash
#!which masscan
#!which nmap
#!which nuclei
#!wget https://github.com/projectdiscovery/nuclei/releases/download/v3.4.7/nuclei_3.4.7_linux_amd64.zip
#!./play.sh start w1 --ips 145.85.0.1/12 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json
#!./play.sh start w2 --ips 145.85.0.1/16 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json
#!./play.sh start w3 --ips 145.85.0.1/18 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json
#!./play.sh status test3
#!./play.sh list
#!./play.sh stop test3
# === Конфигурация ===
SCAN_SCRIPT="scan.py"
TASK_DIR="./tasks"
mkdir -p "$TASK_DIR"

usage() {
  echo "Usage:"
  echo "  $0 start <task_name> [--ips IPs] [--ports PORTS] [--services SRV] [--yaml FILES] [--threads N]"
  echo "  $0 stop <task_name>"
  echo "  $0 status <task_name>"
  echo "  $0 list"
  exit 1
}

start_task() {
  local name="$1"; shift
  local task_path="$TASK_DIR/$name"
  mkdir -p "$task_path"

  local pid_file="$task_path/pid"
  local log_file="$task_path/output.log"
  local err_file="$task_path/error.log"
  local checkpoint="$task_path/scan_checkpoint.json"

  if [ ! -f "$SCAN_SCRIPT" ]; then
    echo "[-] Файл '$SCAN_SCRIPT' не найден!"
    exit 1
  fi

  if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "[!] Задача '$name' уже запущена (PID: $(cat "$pid_file"))"
    exit 1
  fi

  echo "[+] Запуск задачи '$name'..."
  python3 "$SCAN_SCRIPT" "$@" --checkpoint "$checkpoint" >"$log_file" 2>"$err_file" &
  echo $! > "$pid_file"
  echo "[+] PID: $(cat "$pid_file")"
  echo "    Лог: $log_file"
  echo "    Ошибки: $err_file"
}

status_task() {
  local name="$1"
  local task_path="$TASK_DIR/$name"
  local pid_file="$task_path/pid"
  local log_file="$task_path/output.log"
  local err_file="$task_path/error.log"

  if [ ! -f "$pid_file" ]; then
    echo "[-] Нет PID-файла для задачи '$name'"
    exit 1
  fi

  local pid
  pid=$(cat "$pid_file")
  if kill -0 "$pid" 2>/dev/null; then
    echo "[+] Задача '$name' активна (PID: $pid)"
    echo "---- Последние строки log_file:"
    tail -n 5 "$log_file"
    echo "---- Последние строки вывода :"
    tail -n 5 "$err_file"
  else
    echo "[-] Задача '$name' завершена или аварийно остановлена (PID: $pid)"
    echo "    Последние строки log_file:"
    tail -n 5 "$log_file"
    echo "    Последние вывода:"
    tail -n 5 "$err_file"
    rm -f "$pid_file"
  fi
}

stop_task() {
  local name="$1"
  local pid_file="$TASK_DIR/$name/pid"

  if [ ! -f "$pid_file" ]; then
    echo "[-] Нет PID-файла для задачи '$name'"
    exit 1
  fi

  local pid
  pid=$(cat "$pid_file")
  if kill -0 "$pid" 2>/dev/null; then
    echo "[+] Остановка задачи '$name' (PID: $pid)"
    kill "$pid"
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
      echo "[!] Процесс не завершён, принудительная остановка..."
      kill -9 "$pid"
    fi
    rm -f "$pid_file"
  else
    echo "[-] Процесс задачи '$name' уже завершён"
    rm -f "$pid_file"
  fi
}

list_tasks() {
  echo "[+] Список задач:"
  for dir in "$TASK_DIR"/*; do
    [ -d "$dir" ] && basename "$dir"
  done
}

# --- Разбор аргументов ---
case "$1" in
  start)
    shift
    [ $# -lt 1 ] && usage
    task_name="$1"; shift
    start_task "$task_name" "$@"
    ;;
  stop)
    shift
    [ $# -lt 1 ] && usage
    stop_task "$1"
    ;;
  status)
    shift
    [ $# -lt 1 ] && usage
    status_task "$1"
    ;;
  list)
    list_tasks
    ;;
  *)
    usage
    ;;
esac