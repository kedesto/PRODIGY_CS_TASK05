from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}, Protocol: {proto}")

        if TCP in packet and packet[TCP].payload:
            payload = packet[TCP].payload.load
            print("TCP Packet:")
            print(f"Payload: {payload}")
        elif UDP in packet and packet[UDP].payload:
            payload = packet[UDP].payload.load
            print("UDP Packet:")
            print(f"Payload: {payload}")
        elif ICMP in packet and packet[ICMP].payload:
            payload = packet[ICMP].payload.load
            print("ICMP Packet:")
            print(f"Payload: {payload}")

# Start sniffing packets
sniff(prn=packet_callback, store=0)
