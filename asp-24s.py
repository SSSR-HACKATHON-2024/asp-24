#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import signal
import re
import psutil
import uuid
import random
import argparse
import ipaddress
from multiprocessing import Pool
import scanner.core

db = {}

def parse_masscan(file):
    try:
        with open(file, "r") as f:
            result = [line.rstrip("\n").encode("utf-8").decode("utf-8") for line in f]
        result = "\n".join(result)
    except:
        return False
    matches = re.finditer(
        r"Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?Ports: (\d+)", result
    )
    for match in matches:
        ip = match.group(1)
        port = match.group(2)
        if ip not in db:
            db[ip] = {}
        db[ip][port] = {}
    return db


def parse_nmap(nmapfiles):
    for nmapfile in nmapfiles:
        with open(nmapfile, "r") as file:
            lines = '\n'.join(file.readlines())
            try:
                ip = re.search('<address addr="([^"]+)"', lines).group(1)
            except:
                continue
            db[ip] = {}
            db[ip]["ports"] = {}
            matches = re.finditer(
              r'<port protocol="(\w+)" portid="(\d+)"><state state="([^"]+)" reason="[^"]+" reason_ttl="\d+"\/><service name="([^"]*)"( product="([^"]*)")?( version="([^"]*)")?.*?>.*?(<cpe>([^<]*))?',lines
            )
            for match in matches:
                port = match.group(2)
                db[ip]["ports"][port] = {}
                db[ip]["ports"][port]["state"] = match.group(3)
                db[ip]["ports"][port]["service"] = match.group(4)
                db[ip]["ports"][port]["software"] = match.group(6)
                db[ip]["ports"][port]["version"] = match.group(8)
                db[ip]["ports"][port]["protocol"] = match.group(1)
                db[ip]["ports"][port]["cpe"] = match.group(10)
                if not match.group(8) and match.group(10):
                    if match.group(10).count(":") > 3:
                        db[ip]["ports"][port]["version"] = match.group(10).split(":")[-1]
    return db


def nmap(ip, ports, nmapfile, i):
    sb = subprocess.Popen(
        f"nmap -Pn -oX {nmapfile}.{i} -sV {ip} -p{ports} > /dev/null", shell=True
    )
    sb.wait()
    return sb.returncode


def signal_handler(sig, frame):
    if ms:
        ms.terminate()
    sys.exit(0)


def scan_cidr(config, addr):
    global ms
    masscan_file = f"masscan-{config['scan_id']}.txt"
    rate = 1000 if config["stealth"] else 1250000
    print(f"Сканирование CIDR: {addr} со скоростью {rate} пакетов в секунду...")
    masscan_ports = ",".join(scanner.core.config["top_ports"])
    masscan_path = config["masscan_path"]
    ms = subprocess.Popen(
        f"./masscan -p{masscan_ports} --rate {rate} -oG {masscan_path} {addr} > /dev/null 2>&1",
        shell=True,
    )
    ms.wait()
    if ms.returncode < 0:
        quit(f"Masscan завершился с кодом ошибки {ms.returncode}")
    db = parse_masscan(config["masscan_path"])
    return


def scan_ips(config):
    num_cpus = config["threads"] or psutil.cpu_count()
    pool = Pool(processes=num_cpus)
    quick = False
    if quick:
        nmap_ports = ",".join(scanner.core.config["top_ports"])
    else:
        nmap_ports = "0-65535"
    print("Дополнительное сканирование хостов...")
    nmap_path = config["nmap_path"]
    paths = [f"{nmap_path}.{i}" for i in range(len(db.keys()))]
    results = [
        pool.apply_async(
            nmap, args=(host, nmap_ports, nmap_path, list(db.keys()).index(host))
        )
        for host in db.keys()
    ]
    for p in results:
        p.wait()

    parsed_nmap = parse_nmap(paths)


def main(config):
    global ms

    if os.getuid() != 0:
        quit("Данное изделие требует прав администратора.")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    rate = 2500000
    addrs = ["10.0.2.15", "10.0.2.0/24"]
    threads = None

    cwd = sys.path[0]
    directory = f"asp24-scans"
    os.makedirs(directory, exist_ok=True)

    config["scan_id"] = str(uuid.uuid4())
    id = config["scan_id"]

    config["masscan_path"] = os.path.join(directory, f"masscan-{id}.xml")
    config["nmap_path"] = os.path.join(directory, f"nmap-{id}.xml")
    rate_string = f"--rate {rate}" if rate else "--rate 25000"
    for addr in addrs:

        continue
    db[addrs[0]] = {}
    scan_cidr(config, addr)
    scan_ips(config)
    print(db)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(help="Сканируемые хосты (IP или CIDR, можно через запятую)", dest="host", nargs="?")
    parser.add_argument(
        "-q",
        "--quick",
        help="Сканировать только 1000 самых популярных портов",
        dest="quick",
        action="store_true",
    )
    parser.add_argument(
        "-d",
        "--deep",
        help="Сканировать все 65536 портов TCP и UDP с использованием masscan и nmap",
        dest="deep",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--stealth",
        help="Скрытное сканирование",
        dest="stealth",
        action="store_true",
    )
    parser.add_argument(
        "-a",
        "--aggressive",
        help="Агрессивное сканирование",
        dest="aggressive",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--threads",
        help="Задать количество потоков Nmap",
        dest="threads",
        type=int,
    )
    parser.add_argument(

    )
    args = parser.parse_args()
    if (args.quick and args.deep) or (args.stealth and args.aggressive):
        quit("Ошибка: указаны противоречащие параметры")
    config = {
        "threads": args.threads,
        "quick": args.quick,
        "deep": args.deep,
        "aggressive": args.aggressive,
        "stealth": args.stealth,
    }
    main(config)
