from scapy.all import sniff, load_contrib, wrpcap, rdpcap
load_contrib("ikev2")


pkts = rdpcap("dump.pcap")

ike_pkts = [p for p in pkts if p.haslayer(IKEv2)]

exc_pkts = [p for p in ike_pkts if p[IKEv2].exch_type == 34 or p[IKEv2].exch_type == 35 ]
inf_pkts = [p for p in ike_pkts if p[IKEv2].exch_type == 37]
chi_pkts = [p for p in ike_pkts if p[IKEv2].exch_type == 36]

ip_fragments = [pkt for pkt in pkts if IP in pkt and (pkt[IP].flags == 1 or pkt[IP].frag > 0)]

print(f"IKE Packets: {len(ike_pkts)}")
print(f"IKE Exchange Packets: {len(exc_pkts)}")
print(f"INFORMATIONAL Packets: {len(inf_pkts)}")
print(f"CHILD SA Packets: {len(chi_pkts)}")
print(f"Fragment Packets: {len(ip_fragments)}")






total = sum(len(pkt) for pkt in pkts)

print(f"Total Traffic: {total}")
print(f"Protocol Traffic: {sum(len(pkt) for pkt in exc_pkts)}")
print(f"INFORMATIONAL Traffic: {sum(len(pkt) for pkt in inf_pkts)}")
print(f"REKEYING Traffic: {sum(len(pkt) for pkt in chi_pkts)}")
