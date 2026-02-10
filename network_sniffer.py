from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap

captured_packets = []

def packet_analyzer(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print(f"Source: {src_ip}  -->  Destination: {dst_ip}  | Protocol: {protocol}")

        captured_packets.append(packet)

print("Starting Network Sniffer...")
print("Press CTRL + C to stop capture\n")

try:
    sniff(prn=packet_analyzer, store=False)
except KeyboardInterrupt:
    print("\nStopping capture...")

    if captured_packets:
        wrpcap("captured_packets.pcap", captured_packets)
        print("Packets saved as captured_packets.pcap")
    else:
        print("No packets captured.")
        