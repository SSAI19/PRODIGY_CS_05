import scapy.all as scapy

def analyze_packet(pkt):
    # Check if the packet contains an IP layer
    if pkt.haslayer(scapy.IP):
        source_ip = pkt[scapy.IP].src
        dest_ip = pkt[scapy.IP].dst
        ip_protocol = pkt[scapy.IP].proto

        print(f"Source IP: {source_ip} | Destination IP: {dest_ip} | Protocol: {ip_protocol}")

        # Check if it's a TCP packet
        if pkt.haslayer(scapy.TCP):
            try:
                tcp_payload = pkt[scapy.Raw].load
                decoded_tcp_data = tcp_payload.decode('utf-8', 'ignore')
                print(f"TCP Data: {decoded_tcp_data}")
            except (IndexError, UnicodeDecodeError):
                print("Could not decode TCP data.")

        # Check if it's a UDP packet
        elif pkt.haslayer(scapy.UDP):
            try:
                udp_payload = pkt[scapy.Raw].load
                decoded_udp_data = udp_payload.decode('utf-8', 'ignore')
                print(f"UDP Data: {decoded_udp_data}")
            except (IndexError, UnicodeDecodeError):
                print("Could not decode UDP data.")

def initiate_sniffing():
    scapy.sniff(store=False, prn=analyze_packet)

initiate_sniffing()
