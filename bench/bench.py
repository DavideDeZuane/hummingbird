import platform
from scapy.all import sniff, load_contrib, wrpcap
import subprocess
import threading
import docker
import os
import time
import json
from collections import defaultdict
from utils import get_veth, print_container_info

import statistics

load_contrib('ikev2')

from scapy.contrib.ikev2 import *

BPF_FILTER = "udp port 500 or udp port 4500"

CONTAINER_NAME = "client"  

client = docker.from_env()

usage_stats = []


def calculate_cpu_percent(prev, curr):
    cpu_delta = curr['cpu_stats']['cpu_usage']['total_usage'] - prev['cpu_stats']['cpu_usage']['total_usage']
    system_delta = curr['cpu_stats']['system_cpu_usage'] - prev['cpu_stats']['system_cpu_usage']
    num_cpus = len(curr['cpu_stats']['cpu_usage'].get('percpu_usage', [])) or 1

    if system_delta > 0 and cpu_delta > 0:
        return (cpu_delta / system_delta) * num_cpus * 100.0
    else:
        return 0.0

def collect_baseline(container, duration=5, interval=1):
    print(f"Collecting baseline stats for {duration} seconds...")
    cpu_percents = []
    memory_usages = []

    previous = container.stats(stream=False)

    for _ in range(int(duration / interval)):
        time.sleep(interval)
        current = container.stats(stream=False)

        cpu_percent = calculate_cpu_percent(previous, current)
        memory_mb = current['memory_stats']['usage'] / (1024 * 1024)

        cpu_percents.append(cpu_percent)
        memory_usages.append(memory_mb)

        previous = current

    baseline_cpu_avg = statistics.mean(cpu_percents)
    baseline_mem_avg = statistics.mean(memory_usages)
    baseline_mem_std = statistics.stdev(memory_usages) if len(memory_usages) > 1 else 0

    print(f"Baseline CPU (avg): {baseline_cpu_avg:.2f}%")
    print(f"Baseline Memory (avg): {baseline_mem_avg:.2f} MB ± {baseline_mem_std:.2f} MB")

    return baseline_cpu_avg, baseline_mem_avg

def monitor_container(container, stop_event):
    """
    Monitora CPU e memoria del container fino a quando stop_event è settato.
    Usa valori di fallback se 'percpu_usage' non è disponibile.
    """

    while not stop_event.is_set():
        stats = container.stats(stream=False)
        cpu_usage = stats['cpu_stats']['cpu_usage']['total_usage']
        memory_usage = stats['memory_stats']['usage']
            
        print(f"CPU Usage: {cpu_usage} units")
        print(f"Memory Usage: {memory_usage / (1024 * 1024):.2f} MB")

        usage_stats.append({
                "cpu_usage": cpu_usage,
                "memory_usage_mb": memory_usage / (1024 * 1024)
        })
            
        print("Negotiation completed, closing monitoring.")

    return usage_stats

def run_cpu_stress(container_name):
    container = client.containers.get(container_name)

    # Comando Linux CPU-intensive: 'yes > /dev/null' (si ferma quando il comando termina)
    print("⚙️  Example command...")

    # Avvia 'yes > /dev/null' in background, attendi 5 secondi, poi termina
    command = "sh -c 'swanctl --initiate --ike minimal'"

    result = container.exec_run(command, tty=True)
    print(result.output.decode())

if __name__ == "__main__":

    ##############################################################
    # Retreiving some basics infromation
    ##############################################################
    container = client.containers.get(CONTAINER_NAME)
    print_container_info(container)
    collect_baseline(container=container);
    
    ##############################################################

    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_container, args=(container, stop_event))
    monitor_thread.start()
    time.sleep(3)

    run_cpu_stress(CONTAINER_NAME)

    stop_event.set()
    monitor_thread.join()

        # Adesso usage_stats contiene i dati rilevati durante lo stress
    print("Stats raccolte durante lo stress:")
    for stat in usage_stats:
        print(stat)

