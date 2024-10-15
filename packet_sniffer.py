# packet_sniffer.py
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process captured packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Extract source and destination IP addresses
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Extract the protocol (TCP, UDP, ICMP)
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            src_port = None
            dst_port = None
        else:
            protocol = "Other"
            src_port = None
            dst_port = None

        # Print packet information
        print(f"\n[+] Packet Captured: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        if src_port and dst_port:
            print(f"    Ports: {src_port} -> {dst_port}")
        
        # Print raw packet data (payload)
        print(f"    Payload: {bytes(packet[IP].payload)}")

# Sniffing function
def start_sniffing():
    print("Starting packet sniffing... Press Ctrl+C to stop.")
    # Capture packets and call packet_callback for each packet
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffing...")
        exit(0)
