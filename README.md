# fahadafzaal-CyberSec-Task-network-packet-analyzer.py
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process captured packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Define a string to hold protocol name
        protocol_name = "Other"
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"

        # Log basic packet information
        print(f"Packet: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")

        # If the packet has a payload, print its length
        if len(packet) > 0:
            payload = bytes(packet[IP].payload)
            print(f"Payload: {payload[:20]}...")  # Print only first 20 bytes of the payload
            print("-" * 80)

# Start sniffing network packets (on interface 'eth0' or your desired interface)
if __name__ == "__main__":
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=packet_callback, iface="eth0", store=False)
