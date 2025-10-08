from utils.docker import ( is_docker_running, start_docker_linux, docker_compose_up, docker_compose_down, get_veth, exec_in_container)
from utils.monitoring import (get_mem_usage, monitor_container_resources)
import yaml
import subprocess
import threading
import time
import statistics

CONF_FILE = "config.yml"

all_results = []



def run_single_iteration(container_name, connection_name):

    stop_event = threading.Event()
    result_holder = [] 

    monitor_thread = threading.Thread(
        target=monitor_container_resources,
        args=(container_name, stop_event, result_holder),
    )
    monitor_thread.start()
    time.sleep(5)

    exec_in_container(container_name, f"swanctl --initiate --ike {connection_name}")
    time.sleep(5)

    stop_event.set()
    monitor_thread.join()

    metrics = result_holder[0]  # 🔥 recuperi i dati dal thread
    return metrics



if __name__ == "__main__":

    #---------------------------------------------------------------
    # LOAD CONFIGURATION FILE 
    #---------------------------------------------------------------
    print(f"[*] Parsing configuration file {CONF_FILE} ...");
    with open(CONF_FILE) as f:
        config = yaml.safe_load(f)

    ITERATIONS = config["iterations"]
    #---------------------------------------------------------------
    # STARTISTARTIING ENVIRONMENT
    #---------------------------------------------------------------
    if(is_docker_running() == False):
        start_docker_linux();
    print("[*] Docker is running...");
    # check the return value of the command
    docker_compose_up(compose_file=config["compose_file"]);
    print("[*] The environment is running...");

    #---------------------------------------------------------------
    # RESTARTING DAEMON TO RESET ALL CONNCECTION 
    #---------------------------------------------------------------
    #initiator = container.containers.get("responder")
    #INTERFACE = get_veth("responder");
    #print(f"Interface {INTERFACE}")


    for i in range(ITERATIONS):

        metrics = run_single_iteration("initiator_classic", "minimal")
        all_results.append(metrics)

        exec_in_container("initiator_classic", "swanctl --terminate --ike minimal")
        time.sleep(2) 


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

