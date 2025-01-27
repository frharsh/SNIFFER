import socket
import struct

def main():
    # Create a raw socket to sniff packets
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("You need root privileges to run this script!")
        return
    
    print("Sniffer started... Press Ctrl+C to stop.")
    try:
        while True:
            # Receive a packet
            raw_data, addr = sniffer.recvfrom(65536)
            process_packet(raw_data)
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
        sniffer.close()

def process_packet(raw_data):
    # Ethernet Header (first 14 bytes)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    print("\nEthernet Frame:")
    print(f"  Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

    # Process IPv4 packets (EtherType 0x0800)
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        print("IPv4 Packet:")
        print(f"  Version: {version}, Header Length: {header_length}, TTL: {ttl}")
        print(f"  Protocol: {proto}, Source: {src}, Target: {target}")

        # Process TCP packets (protocol 6)
        if proto == 6:
            src_port, dest_port, sequence, acknowledgment, data = tcp_segment(data)
            print("  TCP Segment:")
