from scapy.all import rdpcap
from scapy.layers.inet import UDP, IP, TCP
# import cryptography
import opcode_algorithm
import ack_algorithm
import sys
from openvpn_header import OpenVPN, OpenVPN


def group_conversations(packets):
    conversations = {}
    ids = {}
    for i, packet in enumerate(packets):
        if IP in packet:
            packet_ip:IP = packet[IP]
            port_src = 0
            port_dst = 0
            if UDP in packet:
                port_src = packet[UDP].sport
                port_dst = packet[UDP].dport
            if TCP in packet:
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport

            key = [(packet_ip.src, port_src), (packet_ip.dst, port_dst)]
            key.sort(key=lambda k : k[0] + str(k[1]))
            key = tuple(key)
            if not key in conversations:
                conversations[key] = []
                ids[key] = i
            conversations[key].append(packet)
    
    conversations_with_id = {ids[key]:v for key, v in conversations.items()}
    return conversations

def find_opcodes(packets):
    opcodes = []
    for packet in packets:
        if UDP in packet:
            # application data packets
            packet_udp:UDP = packet[UDP]
            payload = bytes(packet_udp.payload)

            opcode = (payload[0] & 0b11111000) >> 3
            opcodes.append(opcode)
    return opcodes

def flag_openvpn_in_capture(filename):
    packets = rdpcap(filename)
    conversations = group_conversations(packets)

    results = {}
    for key, packets_in_conversation in conversations.items():
        opcodes = find_opcodes(packets_in_conversation)
        results[key] = opcode_algorithm.opcode_fingerprinting(opcodes)
    return results, conversations

def main(argv):
    files = [
        "pcap-dumps/mullvad-ovpn-bridge-mode.pcap",
        # "pcap-dumps/synthesized-openvpn-server-dump.pcap",
        # "pcap-dumps/non-vpn.pcap"
    ]

    if len(argv) > 1:
        files = argv[1:]

    for file in files:
        results, conversations = flag_openvpn_in_capture(file)

        items = list(results.items())
        items.sort(key=lambda k : int(k[1]))
        print(f"\nIdentified {len([i[1] for i in items if i[1]])} of {len(items)} vpn connections in file {file}")
        for (ip1, ip2), result in items:
            print(f"Flagged: {result}\tIn conversation between {ip1} and {ip2}")
            
            ack_flag_result = ack_algorithm.ack_fingerprinting(conversations[(ip1, ip2)])
            print(f"ACK flag result: {ack_flag_result}")


if __name__ == "__main__":
    main(sys.argv)
