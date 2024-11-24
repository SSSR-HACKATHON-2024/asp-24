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
from netaddr import IPRange
from multiprocessing import Pool
import scanner.core

import cve_json_parser
import analytics_module

res_dict = {}


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
        if ip not in res_dict:
            res_dict[ip] = {}
        res_dict[ip][port] = {}
    return res_dict


def parse_nmap(nmapfiles):
    for nmapfile in nmapfiles:
        with open(nmapfile, "r") as file:
            lines = "\n".join(file.readlines())
            try:
                ip = re.search('<address addr="([^"]+)"', lines).group(1)
            except:
                continue
            try:
                ptr = re.search('<hostname name="([^"]+)" type="PTR"\/>',lines).group(1)
                
            except:
                ptr = None
            res_dict[ip] = {}
            res_dict[ip]["ports"] = {}
            matches = re.finditer(
                r'<port protocol="(\w+)" portid="(\d+)"><state state="([^"]+)" reason="[^"]+" reason_ttl="\d+"\/><service name="([^"]*)"( product="([^"]*)")?( version="([^"]*)")?.*?>.*?(<cpe>([^<]*))?',
                lines,
            )
            for match in matches:
                port = match.group(2)
                res_dict[ip]["ports"][port] = {}
                res_dict[ip]["ports"][port]["state"] = match.group(3)
                res_dict[ip]["ports"][port]["service"] = match.group(4)
                res_dict[ip]["ports"][port]["software"] = match.group(6)
                res_dict[ip]["ports"][port]["version"] = match.group(8)
                res_dict[ip]["ports"][port]["protocol"] = match.group(1)
                res_dict[ip]["ports"][port]["cpe"] = match.group(10)
                res_dict[ip]["ports"][port]["domain"] = ptr
                if not match.group(8) and match.group(10):
                    if match.group(10).count(":") > 3:
                        res_dict[ip]["ports"][port]["version"] = match.group(10).split(
                            ":"
                        )[-1]
    return res_dict


def nmap_aggressive(ip, ports, nmapfile, i):
    sb = subprocess.Popen(
        f"nmap -T5 -Pn -r -oX {nmapfile}.{i} -sV  {ip} -p{ports} > /dev/null", shell=True
    )
    sb.wait()
    return sb.returncode


def nmap_stealthy(ip, ports, nmapfile, i):
    sb = subprocess.Popen(
        f"nmap -T1 -Pn -oX -r {nmapfile}.{i} -sV {ip} -p{ports} > /dev/null", shell=True
    )
    sb.wait()
    return sb.returncode


def signal_handler(sig, frame):
    if ms:
        ms.terminate()
    sys.exit(0)


def scan_cidr(config):
    global ms
    res_dict = {}
    masscan_path = config["masscan_path"]
    rate = 2500 if config["stealth"] else 1250000
    masscan_ports = (
        "0-65535" if config["deep"] else ",".join(scanner.core.config["top_ports"])
    )
    print(f"Предварительное сканирование узлов с использованием Masscan")
    addr = ",".join(config["cidrs"])
    ms = subprocess.Popen(
        f"/opt/asp-24/masscan -p{masscan_ports} --rate {rate} -oG {masscan_path} {addr} ",  # > /dev/null 2>&1
        shell=True,
    )
    ms.wait()
    if ms.returncode < 0:
        quit(f"Masscan завершился с кодом ошибки {ms.returncode}")
    res_dict = parse_masscan(masscan_path)
    return res_dict


def scan_ips(config):
    num_cpus = config["threads"] or psutil.cpu_count()
    pool = Pool(processes=num_cpus)
    quick = config["quick"]
    if quick:
        nmap_ports = ",".join(scanner.core.config["top_ports"])
    else:
        nmap_ports = "0-65535"
    print("Углубленное сканирование хостов с использованием Nmap")
    nmap_path = config["nmap_path"]
    paths = [f"{nmap_path}.{i}" for i in range(len(res_dict.keys()))]
    results = [
        pool.apply_async(
            nmap_stealthy if config["stealth"] else nmap_aggressive,
            args=(host, nmap_ports, nmap_path, list(res_dict.keys()).index(host)),
        )
        for host in res_dict.keys()
    ]
    for p in results:
        p.wait()

    parsed_nmap = parse_nmap(paths)


def main(config):
    if os.getuid() != 0:
        quit("Данное изделие требует прав администратора.")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    cwd = sys.path[0]
    directory = f"asp24-scans"
    os.makedirs(directory, exist_ok=True)

    config["scan_id"] = str(uuid.uuid4())
    id = config["scan_id"]

    config["masscan_path"] = os.path.join(directory, f"masscan-{id}.txt")
    config["nmap_path"] = os.path.join(directory, f"nmap-{id}.xml")

    if len(config['cidrs']) > 0:
        scan_cidr(config)
    scan_ips(config)
    return res_dict, config["scan_id"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        help="Сканируемые хосты (IP или CIDR, можно через запятую)",
        dest="host",
        nargs="?",
    )
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
    args = parser.parse_args()
    if (args.quick and args.deep) or (args.stealth and args.aggressive):
        quit("Ошибка: указаны противоречащие параметры")
    config = {
        "threads": args.threads,
        "quick": args.quick,
        "deep": args.deep,
        "aggressive": args.aggressive,
        "stealth": args.stealth,
        "addrs": args.host,
        "cidrs": [],
    }
    if args.host is None:
        quit("Не предоставлены цели для сканирования")
    for addr in config["addrs"].split(","):
        netrange = addr.split("-")
        if len(netrange) > 1:
            try:
                iprange = IPRange(netrange[0], netrange[1])
                config["cidrs"].append(addr)
            except:
                quit(f"Неверный диапазон IP-адресов: {addr}")
        else:
            try:
                ip = ipaddress.ip_network(addr)
                if str(ip.netmask) == "255.255.255.255":
                    res_dict[addr] = {}
                else:
                    config["cidrs"].append(addr)
            except:
                quit(f"Неверный IP или CIDR: {addr}")
    res_dict, scan_id = main(config)
    filtered_dict = {}
    for i in res_dict.keys():
        if 'ports' in res_dict[i]:
            filtered_dict[i] = res_dict[i]
    if len(filtered_dict.keys()) > 0:
        print("Передача полученных данных в СУБД...")
        cve_json_parser.main_cve_DB()
        analytics_module.main_anlt_module(filtered_dict, scan_id)