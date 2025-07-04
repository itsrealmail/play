#!/usr/bin/env python3

import os
import json
from flask import Flask, render_template_string

TASK_DIR = "./tasks"

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<title>Сканер: Статистика задач</title>
<h2>Статистика задач</h2>
<table border=1 cellpadding=6>
<tr>
  <th>Имя задачи</th>
  <th>PID</th>
  <th>Всего целей</th>
  <th>Выполнено</th>
  <th>Осталось</th>
  <th>YAML-файлов</th>
</tr>
{% for task in tasks %}
<tr>
  <td>{{task['name']}}</td>
  <td>{{task['pid']}}</td>
  <td>{{task['total']}}</td>
  <td>{{task['done']}}</td>
  <td>{{task['todo']}}</td>
  <td>{{task['yaml_count']}}</td>
</tr>
{% endfor %}
</table>
<br>
<small>Обновите страницу для актуального статуса.</small>
"""

def parse_checkpoint(checkpoint_path):
    if not os.path.exists(checkpoint_path):
        return {}
    with open(checkpoint_path, 'r') as f:
        return json.load(f)

def get_task_stats():
    tasks = []
    for tname in os.listdir(TASK_DIR):
        tpath = os.path.join(TASK_DIR, tname)
        if not os.path.isdir(tpath):
            continue
        pid_file = os.path.join(tpath, 'pid')
        checkpoint_file = os.path.join(tpath, 'scan_checkpoint.json')
        pid = None
        if os.path.exists(pid_file):
            with open(pid_file) as f:
                pid = f.read().strip()
        checkpoint = parse_checkpoint(checkpoint_file)
        done = len(checkpoint)
        all_targets = set()
        yamls = set()
        for k in checkpoint:
            if "|" in k:
                url, yamlfile = k.split("|", 1)
                all_targets.add(url)
                yamls.add(yamlfile)
        total = done
        yaml_count = len(yamls) if yamls else "?"
        targets_file = os.path.join(tpath, "targets.json")
        if os.path.exists(targets_file):
            with open(targets_file) as f:
                targets = json.load(f)
                total = len(targets) * max(1, yaml_count if yaml_count != "?" else 1)
        todo = max(0, total - done)
        tasks.append({
            "name": tname,
            "pid": pid if pid else "-",
            "total": total,
            "done": done,
            "todo": todo,
            "yaml_count": yaml_count,
        })
    return tasks

@app.route("/")
def index():
    tasks = get_task_stats()
    return render_template_string(TEMPLATE, tasks=tasks)

if __name__ == "__main__":
    import sys
    host = "127.0.0.1"
    port = 5000
    if "--host" in sys.argv:
        hidx = sys.argv.index("--host") + 1
        if hidx < len(sys.argv):
            host = sys.argv[hidx]
    if "--port" in sys.argv:
        pidx = sys.argv.index("--port") + 1
        if pidx < len(sys.argv):
            port = int(sys.argv[pidx])
    app.run(host=host, port=port, debug=True)