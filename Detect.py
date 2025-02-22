    from scapy.all import sniff, TCP, IP, ICMP
    from collections import defaultdict

    # Data structures to store packet counts
    syn_floods = defaultdict(int)
    icmp_floods = defaultdict(int)
    tcp_flags = defaultdict(int)

    # Detect Christmas Tree Scan
    def detect_christmas_tree(pkt):
        if pkt.haslayer(TCP):
            tcp_flags_comb = pkt[TCP].flags
            if tcp_flags_comb & 0b00101001 == 0b00101001:  # FIN, PSH, URG set
                print(f"[ALERT] Christmas Tree Scan detected from {pkt[IP].src} to {pkt[IP].dst}")


    # Detect SYN Flood
    def detect_syn_flood(pkt):
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":  # SYN flag
            syn_floods[pkt[IP].src] += 1
            if syn_floods[pkt[IP].src] > 50:  # Threshold can be adjusted as needed
                print(f"SYN Flood detected from {pkt[IP].src} to {pkt[IP].dst}")

    # Detect ICMP Flood
    def detect_icmp_flood(pkt):
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo Request
            icmp_floods[pkt[IP].src] += 1
            if icmp_floods[pkt[IP].src] > 100:  # Threshold can be adjusted as needed
                print(f"ICMP Flood detected from {pkt[IP].src} to {pkt[IP].dst}")

    # Handle each packet and check for attacks
    def packet_handler(pkt):
        detect_christmas_tree(pkt)
        detect_syn_flood(pkt)
        detect_icmp_flood(pkt)

    # Start sniffing the network
    def start_sniffing():
        print("Starting packet capture...")
        sniff(filter="ip", prn=packet_handler, store=0)  # 'store=0' avoids storing packets to save memory, otherwise you can store it to a different output file

    # Run the detection tool
    if __name__ == "__main__":
        start_sniffing()
