import platform
from scapy.all import sniff, load_contrib, wrpcap
import subprocess
import threading
import docker
import time
import json
from collections import defaultdict
from utils import get_veth

load_contrib('ikev2')

from scapy.contrib.ikev2 import *

BPF_FILTER = "udp port 500 or udp port 4500"

CONTAINER_NAME = "ike"  

client = docker.from_env()

captured_packets = []
captured_stats = []

tot_traffic = 0
ike_traffic = 0

exchange_groups = defaultdict(list)

def analyze_pcap():
    global tot_traffic, ike_traffic
    for packet in captured_packets:
        print(packet.sprintf("%IP.len%"))
        tot_traffic += len(packet)
        
        if packet.haslayer(IKEv2):
            ikev2_payload = packet[IKEv2]
            ike_traffic += ikev2_payload.length
            print(ikev2_payload)
            if ikev2_payload.exch_type == 34:
                exchange_groups["INIT"].append(packet)
            elif ikev2_payload.exch_type == 35:
                exchange_groups["AUTH"].append(packet)
            elif ikev2_payload.exch_type == 43:
                exchange_groups["INTE"].append(packet)
            else:
                print("Unknow Exchange") 
        
def analyze_exchange_group(exchange_groups):
    print("-" * 40)
    for exch_type, pkts in exchange_groups.items():
        print(f"Exchange Type: {exch_type}")
        print(f"Number of packets: {len(pkts)}")
        
        total_bytes = sum(len(pkt) for pkt in pkts)
        print(f"Total bytes: {total_bytes} bytes")

        timestamps = [pkt.time for pkt in pkts]
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
        print(f"Duration: {duration:.6f} seconds")
        
        print("-" * 40)

def is_docker_running():
    """Check if docker is running."""
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        print("Docker non installed..")
        sys.exit(1)

def start_docker_linux():
    """Avvia Docker su Linux."""
    print("Starting Docker on Linux...")
    subprocess.run(["sudo", "systemctl", "start", "docker"], check=True)
    time.sleep(3)

def get_container_stats(container_id):
    stats = client.containers.get(container_id).stats(stream=False)
    return stats

def monitor_initiator_container():
    print(f"Monitoring the initiator container: {CONTAINER_NAME}")
    container = client.containers.get(CONTAINER_NAME)
    try:
        start_time = time.perf_counter()  
        while not stop_event.is_set(): 

            stats = container.stats(stream=False)
            cpu_usage = stats['cpu_stats']['cpu_usage']['total_usage']
            memory_usage = stats['memory_stats']['usage']
            
            print(f"CPU Usage: {cpu_usage} units")
            print(f"Memory Usage: {memory_usage / (1024 * 1024):.2f} MB")

            captured_stats.append({
                "cpu_usage": cpu_usage,
                "memory_usage_mb": memory_usage / (1024 * 1024)
            })
            
        print("Negotiation completed, closing monitoring.")
    
    except KeyboardInterrupt:
        print("Forced stop.")

def packet_callback(packet):
    """
    Add the packet captured to a global variable, this variable will be saved in a pcap file
    """
    captured_packets.append(packet);
            
def start_ike_negotiation():
    """
    This function will be used to start the IKE Negotiation inside the container
    """
    print("Starting IKE negotiation...")
    ike_command = f"./hummingbird"

    try:
        start = time.perf_counter()
        result = client.containers.get(CONTAINER_NAME).exec_run(ike_command, tty=True, stdin=False)
        end = time.perf_counter()
        print("Running command inside the container...")
        if(result.exit_code == 0):
            print("Command successfully")
            print(f"time taken: {end-start}")
            stop_event.set() 
    except Exception as e:
        print(f"Errore nell'eseguire il comando IKE: {e}")

def sniff_packets(interface):
    print(f"Sniffing on container interface: {interface}")
    
    sniff(iface=interface, filter=BPF_FILTER, prn=packet_callback, store=False, timeout=5)

def clean_environment():
    try:
        exec_cmd = client.containers.get(CONTAINER_NAME).exec_run(f"swanctl --terminate --ike {CONNECTION_NAME}", privileged=True)
        print(f"Closing all open Security Association...")
    except Exception as e:
        print(f"Errore nella terminazione SA: {e}")

if __name__ == "__main__":

    system = platform.system()
    
    if is_docker_running():
        print("Docker is running...")
    else:
        print("Starting docker")
        if system == "Linux":
            start_docker_linux();
        else:
            print("Please use a Linux system")

    INTERFACE = get_veth(CONTAINER_NAME)
    print(INTERFACE);

    stop_event = threading.Event()
    clean_environment()

    monitor_thread = threading.Thread(target=monitor_initiator_container, args=())
    ike_thread = threading.Thread(target=start_ike_negotiation)
    network_thread = threading.Thread(target=sniff_packets, args=(INTERFACE,))

    time.sleep(2)
    monitor_thread.start()
    time.sleep(3)
    network_thread.start()
    ike_thread.start()
    
    ike_thread.join()
    monitor_thread.join()
    network_thread.join()
    wrpcap("ikev2_traffic.pcap", captured_packets)
    container = client.containers.get(CONTAINER_NAME)
    stats = container.stats(stream=False)
    cpu_usage = stats['cpu_stats']['cpu_usage']['total_usage']
    memory_usage = stats['memory_stats']['usage']
    captured_stats.append({
            "cpu_usage": cpu_usage,
                "memory_usage_mb": memory_usage / (1024 * 1024)
    })
    analyze_pcap()
    analyze_exchange_group(exchange_groups)
    print(f"Total Traffic: {tot_traffic}")
    print(f"IKE Traffic: {ike_traffic}")

    cpu_usage_values = [entry['cpu_usage'] for entry in captured_stats]
    memory_usage_values = [entry['memory_usage_mb'] for entry in captured_stats]

    cpu_max = max(cpu_usage_values)
    cpu_min = min(cpu_usage_values)
    memory_max = max(memory_usage_values)
    memory_min = min(memory_usage_values)

    cpu_usage_diff = cpu_max - cpu_min
    memory_usage_diff = memory_max - memory_min

    print(f"CPU Usage Difference: {cpu_usage_diff/1000000} ms")
    print(f"Memory Usage Difference: {memory_usage_diff} MB")
    print(f"Memory Usage Peak: {memory_max} MB")
    




