import csv
from collections import defaultdict
from scapy.all import sniff, load_contrib, wrpcap, rdpcap

load_contrib('ikev2')

from scapy.contrib.ikev2 import *

TRAFFIC_DUMP = "ikev2_traffic.pcap"

exchange_groups = defaultdict(list)

def load_decryption_table(csv_file):
    decryption_table = []
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            # Supponiamo che la struttura del CSV sia sempre la stessa (6 colonne)
            decryption_table.append({
                "SPIi": row[0],
                "SPIr": row[1],
                "SK_ei": row[2],
                "SK_er": row[3],
                "encryption_algorithm": row[4],
                "SK_ai": row[5],
                "SK_ar": row[6],
                "authentication_algorithm": row[7],
            })
    return decryption_table

def get_last_encryption_key(decryption_table):
    # Ottieni l'ultima entry dato che se ci sono più scambi la chiave viene raffindata
    last_entry = decryption_table[-1]
    return last_entry

def analyze_pcap(pcap_file, decryption_table):

    packets = rdpcap(pcap_file)

    for packet in packets:
        if packet.haslayer(IKEv2):
            ikev2_payload = packet[IKEv2]
            # SUDDIVIDERE I PACCHETTI IN BASE ALLO SCAMBIO
            if ikev2_payload.exch_type == 34:
                exchange_groups["INIT"].append(packet)
            elif ikev2_payload.exch_type == 35:
                exchange_groups["AUTH"].append(packet)
            elif ikev2_payload.exch_type == 43:
                exchange_groups["INTE"].append(packet)
            else:
                print("Unknow Exchange") 
        
def analyze_exchange_group(exchange_groups):
    for exch_type, pkts in exchange_groups.items():
        print(f"Exchange Type: {exch_type}")
        print(f"Number of packets: {len(pkts)}")
        
        total_bytes = sum(len(pkt) for pkt in pkts)
        print(f"Total bytes: {total_bytes} bytes")
        
        # Timestamp calcolo
        timestamps = [pkt.time for pkt in pkts]
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
        print(f"Duration: {duration:.6f} seconds")
        
        print("-" * 40)



# Carica la decryption table
decryption_table = load_decryption_table('keys/ikev2_decryption_table')
last = get_last_encryption_key(decryption_table)
"""
print("############### IKE SA ################")
print("Encryption:")
print(f"\tAlgorithm: {last["encryption_algorithm"]}")
print(f"\tSK_ei: {last["SK_ei"]}")
print(f"\tSK_er: {last["SK_er"]}")
print("Authentication:")
print(f"\tAlgorithm: {last["authentication_algorithm"]}")
print(f"\tSK_ai: {last["SK_ai"]}")
print(f"\tSK_ar: {last["SK_ar"]}")
"""

analyze_pcap(pcap_file=TRAFFIC_DUMP, decryption_table=last)
analyze_exchange_group(exchange_groups)