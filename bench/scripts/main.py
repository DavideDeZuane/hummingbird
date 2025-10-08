from utils.docker import ( is_docker_running, start_docker_linux, docker_compose_up, docker_compose_down, get_veth, exec_in_container)
from utils.monitoring import (get_mem_usage, monitor_container_resources)
from utils.plot import (plot_memory_distribution)
from utils.save import (save_benchmark_results)
import yaml
import subprocess
import threading
import time
import statistics

CONF_FILE = "config.yml"

all_results = []


def run_single_iteration(container_name, connection_name):


    ########################################################################à
    # RENDERE LA FUNZIONE CONDIZIONALE IN BASE A QUALE INITIATOR SI UTILIZZA
    ########################################################################à

    stop_event = threading.Event()
    result_holder = [] 

    monitor_thread = threading.Thread(
        target=monitor_container_resources,
        args=(container_name, stop_event, result_holder),
    )
    monitor_thread.start()
    time.sleep(5)

    result = exec_in_container(container_name, f"swanctl --initiate --ike {connection_name}")
    time.sleep(5)

    stop_event.set()
    monitor_thread.join()

    metrics = result_holder[0]  
    return metrics



if __name__ == "__main__":
    #---------------------------------------------------------------
    # LOAD CONFIGURATION FILE 
    #---------------------------------------------------------------
    print(f"[=] Parsing configuration file {CONF_FILE} ...");
    with open(CONF_FILE) as f:
        config = yaml.safe_load(f)

    ITERATIONS = config["iterations"]
    RESULTS_DIR = config["results_dir"] 
    COMPOSE_FILE = config["compose_file"]
    CONNECTION_NAME = config["connection_name"]
    CONTAINER_RESPONDER = config["container_responder"]
    CONTAINER_INITIATOR = config["container_initiator"]
    print(f"[+] Configuration settings loaded ...");
    #---------------------------------------------------------------
    # STARTING ENVIRONMENT
    #---------------------------------------------------------------
    if(is_docker_running() == False):
        start_docker_linux();
    print("[*] Docker is running...");
    docker_compose_up(COMPOSE_FILE);
    print("[*] The environment is running...");
    #---------------------------------------------------------------
    # STARTING SIMULATION
    #---------------------------------------------------------------
    for i in range(ITERATIONS):

        metrics = run_single_iteration(CONTAINER_INITIATOR, CONNECTION_NAME)
        all_results.append(metrics)

        exec_in_container(CONTAINER_INITIATOR, f"swanctl --terminate --ike {CONNECTION_NAME}")
        time.sleep(2) 
        print("[✔] Environemnt Cleaned")


      # --- Aggrega i risultati ---
    memory_peaks = [r["memory_peak"] for r in all_results]
    memory_avgs = [r["memory_avg"] for r in all_results]

    summary = {
        "memory_avg_mean": statistics.mean(memory_avgs),
        "memory_avg_std": statistics.stdev(memory_avgs),
        "memory_peak_mean": statistics.mean(memory_peaks),
        "memory_peak_std": statistics.stdev(memory_peaks),
    }
    #docker_compose_down(compose_file=config["compose_file"]);

    print(summary)

    plot_memory_distribution(memory_avgs, title="Distribuzione Memoria Media", save_path="../results/memory_avg_dist.png")
    plot_memory_distribution(memory_peaks, title="Distribuzione Picco Memoria", save_path="../results/memory_peak_dist.png")

save_benchmark_results(all_results, summary, output_path="../results/initiator_classic_benchmark.json")
