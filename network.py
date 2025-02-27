import scapy.all as scapy
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            try:
                payload = packet[scapy.Raw].load
                decord_payload = payload.decode('utf-8','ignore')
                print(f"TCP Payload first 50 character: {decord_payload[:50]}")
            except (IndexError,UnicodeDecodeError):
                print("unable to decode TCP payload.")

        elif packet.haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decord_payload = payload.decode('utf-8','ignore')
                print(f"UDP Payload first 50 character: {decord_payload[:50]}")
            except (IndexError,UnicodeDecodeError):
                print("unable to decode UDP payload.")

def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback)
start_sniffing()