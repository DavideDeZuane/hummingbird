from utils.docker import ( is_docker_running, start_docker_linux, docker_compose_up, docker_compose_down, get_veth, exec_in_container)
from utils.monitoring import (get_mem_usage, monitor_container_resources)
from utils.save import (save_benchmark_results)
import yaml
import subprocess
import threading
import time
import os
import statistics

CONF_FILE = "config.yml"

all_results = []

def run_single_iteration(container_name, command):

    stop_event = threading.Event()
    result_holder = [] 

    monitor_thread = threading.Thread(
        target=monitor_container_resources,
        args=(container_name, stop_event, result_holder),
    )
    monitor_thread.start()
    time.sleep(5)

    result = exec_in_container(container_name, command)
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

    if CONTAINER_INITIATOR == "initiator_minimal":
        CMD_UP = "./build/main" # definire in base al container
    else:
        CMD_UP = f"swanctl --initiate --ike {CONNECTION_NAME}"

    # Il reset della connessione lo facciamo fare al responder in modo tale da evitare che questo vada ad impattare 
    # sulle misurazioni fatte per il responder anche se comunque viene fatta al di fuori de monitoring, inoltre serve
    # perchè l'initioator minimal non è ancora in grado di farlo
    CMD_DOWN = f"swanctl --terminate --ike {CONNECTION_NAME}"
    
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

        metrics = run_single_iteration(CONTAINER_INITIATOR, CMD_UP)
        all_results.append(metrics)

        exec_in_container(CONTAINER_RESPONDER, CMD_DOWN) 
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

    timestamp = int(time.time())
    os.makedirs("../results", exist_ok=True)



    RESULT_PATH = f"../results/{timestamp}_{CONTAINER_INITIATOR}_{CONNECTION_NAME}.json"

    save_benchmark_results(all_results, summary, output_path=RESULT_PATH)
    print(f"[+] Benchmark saved in: {RESULT_PATH}")

