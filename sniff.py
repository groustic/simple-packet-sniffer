import socket
import struct

def main():
    # Create a raw socket
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("[*] Starting packet sniffer...")

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(proto), data[14:]

def mac_format(mac_bytes):
    mac = map('{:02x}'.format, mac_bytes)
    return ':'.join(mac).upper()

if __name__ == "__main__":
    main()
