from scapy.all import rdpcap
from scapy.layers.inet import UDP, IP
# import cryptography
import opcode_algorithm
import ack_algorithm
import sys


def group_conversations(packets):
    conversations = {}
    for packet in packets:
        if IP in packet:
            packet_ip:IP = packet[IP]

            key = [packet_ip.src, packet_ip.dst]
            key.sort()
            key = tuple(key)
            if not key in conversations:
                conversations[key] = []
            conversations[key].append(packet)
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
        #"pcap-dumps/synthesized-openvpn-server-dump.pcap",
        #"pcap-dumps/non-vpn.pcap"
    ]  

    for file in files:
        results, conversations = flag_openvpn_in_capture(file)

        items = list(results.items())
        items.sort(key=lambda k : int(k[1]))
        print(f"\nIdentified {len([i[1] for i in items if i[1]])} vpn connections in file {file}")
        for (ip1, ip2), result in items:
            print(f"Flagged: {result}\tIn conversation between {ip1} and {ip2}")
            ack_flag_result = ack_algorithm.ack_fingerprinting(conversations[(ip1, ip2)])
            print(f"ACK flag result: {ack_flag_result}")


if __name__ == "__main__":
    main(sys.argv)
