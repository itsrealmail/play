#!/usr/bin/env python3

import subprocess
import os
import sys
import ssl
import socket
import threading
import queue
import json
import signal
import logging
from pathlib import Path
import tempfile
import argparse

logging.basicConfig(
    filename='scan.log',
    level=logging.DEBUG,  # Было INFO
    format='%(asctime)s [%(levelname)s] %(message)s'
)

lock = threading.Lock()
stop_event = threading.Event()

def parse_args():
    ...
    parser.add_argument('--log-file', required=False, help='Path to log file')
    ...
def main():
    args = parse_args()
    if args.log_file:
        logging.getLogger().handlers.clear()
        logging.basicConfig(
            filename=args.log_file,
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(message)s'
        )
    ...

def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated Recon Script (non-interactive, threaded, resumable)"
    )
    parser.add_argument('--ips', required=True, help='Comma-separated IP ranges (e.g. 192.168.0.0/24,10.0.0.1)')
    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument('--ports', help='Ports to scan (e.g. 80,443 or 20-25 or 21,22,80-100)')
    port_group.add_argument('--ports-file', help='File with ports (one per line or comma-separated)')
    parser.add_argument('--services', required=True, help='Comma-separated keywords for services (e.g. nginx,exchange)')
    parser.add_argument('--yaml', required=True, help='Comma-separated paths to nuclei YAML files')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads for nuclei')
    parser.add_argument('--checkpoint', type=str, default="scan_checkpoint.json", help='Checkpoint file')
    parser.add_argument('--rate', type=int, default=1000, help='Masscan rate')
    parser.add_argument('--log-file', required=False, help='Path to log file')
    return parser.parse_args()


def parse_ports(args):
    if args.ports:
        return args.ports.strip()
    elif args.ports_file:
        ports = []
        ports_file = Path(args.ports_file)
        if not ports_file.exists():
            logging.error(f"Ports file '{ports_file}' not found")
            sys.exit(1)
        with open(ports_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                ports.extend([p.strip() for p in line.split(',') if p.strip()])
        return ','.join(ports)
    else:
        logging.error("No ports specified.")
        sys.exit(1)


def run_masscan(ip_ranges, ports, output_file="masscan_output.txt", rate=1000):
    ip_arg = ','.join(ip_ranges)
    logging.info(f"Running masscan on {ip_arg} ports {ports}")
    cmd = [
        "sudo", "masscan", ip_arg,
        "--ports", ports,
        "--rate", str(rate),
        "-oL", output_file
    ]
    try:
        subprocess.run(cmd, check=True)
        logging.info(f"Masscan results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Masscan failed: {e}")
        sys.exit(1)


def parse_masscan_output(output_file):
    targets = set()
    if not Path(output_file).exists():
        logging.error(f"Masscan output file '{output_file}' not found")
        return []
    with open(output_file, 'r') as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[3]
                port = parts[2]
                targets.add((ip, port))
    return sorted(targets)


def run_nmap_and_filter(ip_port_list, keywords, filtered_output_file="nmap_filtered_output.txt"):
    logging.info(f"Running nmap on {len(ip_port_list)} targets, filtering for {keywords}")
    tmp_fd, tmp_path = tempfile.mkstemp(text=True)
    try:
        with os.fdopen(tmp_fd, "w") as f:
            for ip, port in ip_port_list:
                f.write(f"{ip} -p {port}\n")
        cmd = [
            "nmap", "-sV",
            "--script", "banner,vuln",
            "-iL", tmp_path
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            logging.error(f"Nmap error: {result.stderr}")
            sys.exit(1)
        filtered_lines = []
        current_ip = None
        for line in result.stdout.splitlines():
            if line.startswith("Nmap scan report for"):
                current_ip = line.strip().split()[-1]
            for keyword in keywords:
                if keyword.lower() in line.lower():
                    filtered_lines.append(f"{current_ip}: {line.strip()}")
        if filtered_lines:
            with open(filtered_output_file, "w") as f:
                for line in filtered_lines:
                    f.write(line + "\n")
            logging.info(f"Filtered nmap results saved to {filtered_output_file}")
        else:
            logging.warning("No matches found for the specified services")
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def detect_tls(ip, port, timeout=2):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                return True
    except Exception:
        return False


def format_url(ip, port):
    scheme = "https" if detect_tls(ip, port) else "http"
    return f"{scheme}://{ip}:{port}"


def load_checkpoint(checkpoint_file):
    if Path(checkpoint_file).exists():
        with open(checkpoint_file, "r") as f:
            return json.load(f)
    return {}


def save_checkpoint(data, checkpoint_file):
    with lock:
        with open(checkpoint_file, "w") as f:
            json.dump(data, f, indent=2)


def scan_worker(q, yamls, checkpoint, checkpoint_file):
    while not q.empty() and not stop_event.is_set():
        ip, port = q.get()
        url = format_url(ip, port)
        for yaml_path in yamls:
            task_id = f"{url}|{yaml_path}"
            with lock:
                if task_id in checkpoint:
                    continue
            logging.info(f"Scanning {url} with {yaml_path}")
            try:
                subprocess.run(["nuclei", "-u", url, "-t", str(yaml_path)], check=True)
                with lock:
                    checkpoint[task_id] = "done"
                    save_checkpoint(checkpoint, checkpoint_file)
            except subprocess.CalledProcessError:
                logging.error(f"Scan failed: {url} with {yaml_path}")
        q.task_done()


def run_nuclei_multithread(ip_port_list, yaml_files, checkpoint_file, threads=4):
    logging.info(f"Starting nuclei with {threads} threads and pause/resume support")
    target_queue = queue.Queue()
    checkpoint = load_checkpoint(checkpoint_file)
    for ip, port in ip_port_list:
        target_queue.put((ip, port))
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=scan_worker, args=(target_queue, yaml_files, checkpoint, checkpoint_file))
        t.daemon = True
        t.start()
        thread_list.append(t)
    try:
        for t in thread_list:
            t.join()
    except KeyboardInterrupt:
        logging.warning("Interrupted by user, saving checkpoint...")
        stop_event.set()
        save_checkpoint(checkpoint, checkpoint_file)
        sys.exit(0)
    save_checkpoint(checkpoint, checkpoint_file)


def main():
    args = parse_args()
    ip_ranges = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
    ports = parse_ports(args)
    keywords = [s.strip().lower() for s in args.services.split(",") if s.strip()]
    yaml_files = [Path(y.strip()) for y in args.yaml.split(",") if Path(y.strip()).exists()]
    if not yaml_files:
        logging.error("No valid nuclei YAML files provided")
        sys.exit(1)
    checkpoint_file = args.checkpoint

    run_masscan(ip_ranges, ports, rate=args.rate)
    ip_port_pairs = parse_masscan_output("masscan_output.txt")
    if not ip_port_pairs:
        logging.warning("No live hosts found")
        sys.exit(1)
    run_nmap_and_filter(ip_port_pairs, keywords)
    run_nuclei_multithread(ip_port_pairs, yaml_files, checkpoint_file, threads=args.threads)
    logging.info("Scan complete.")


if __name__ == "__main__":
    main()