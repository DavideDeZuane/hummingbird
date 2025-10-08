from utils.docker import docker_client
from utils.log import *
import time, statistics


def get_mem_usage(container_name: str):
    container = docker_client.containers.get(container_name)
    stats = container.stats(stream=False)
    return stats["memory_stats"]["usage"] / (1024 * 1024)


def monitor_container_resources(container_name: str, stop_event, result_holder, interval=0.5):
    container = docker_client.containers.get(container_name)

    memory_samples = []
    prev_stats = container.stats(stream=False)
    
    print(f"[=] Starting monitoring for '{container_name}' ...")

    try:
        while not stop_event.is_set():
            stats = container.stats(stream=False)
            mem_mb = stats["memory_stats"]["usage"] / (1024 * 1024)
            memory_samples.append(mem_mb)

            prev_stats = stats
            time.sleep(interval)

    except KeyboardInterrupt:
        print("Monitoraggio interrotto manualmente.")
    finally:
        log_ok("Monitoring finished")

    memory_avg = statistics.mean(memory_samples)
    memory_peak = max(memory_samples)
    memory_std = statistics.stdev(memory_samples) if len(memory_samples) > 1 else 0.0

    log_ok(f"Memory avg: {memory_avg:.2f} MB ± {memory_std:.2f}")
    log_ok(f"Memory peak: {memory_peak:.2f} MB")


    results =  {
        "memory_avg": memory_avg,
        "memory_std": memory_std,
        "memory_peak": memory_peak,
    }

    result_holder.append(results)