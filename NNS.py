import socket
import struct

def main():
    try:
        # Create a raw socket to sniff packets
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
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    print("\nEthernet Frame:")
    print(f"  Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

    if eth_proto == 8:  # IPv4
        version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
        print("IPv4 Packet:")
        print(f"  Version: {version}, Header Length: {header_length}, TTL: {ttl}")
        print(f"  Protocol: {proto}, Source: {src}, Target: {target}")

        if proto == 6:  # TCP
            src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, data = tcp_segment(data)
            print("  TCP Segment:")
            print(f"    Source Port: {src_port}, Destination Port: {dest_port}")
            print(f"    Sequence: {sequence}, Acknowledgment: {acknowledgment}")
            print(f"    Flags: {offset_reserved_flags}")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]

def get_mac(bytes_addr):
    return ":".join(f"{b:02x}" for b in bytes_addr)

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("!8xBB2x4s4s", data[:20])
    return version, header_length, ttl, proto, get_ip(src), get_ip(target), data[header_length:]

def get_ip(bytes_addr):
    return ".".join(map(str, bytes_addr))

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack("!HHLLH", data[:14])
    return src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, data[20:]

if __name__ == "__main__":
    main()
