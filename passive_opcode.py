from scapy.all import rdpcap
from scapy.layers.inet import UDP, IP
# import cryptography
import opcode_algorithm
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
            packet_ip:UDP = packet[UDP]
            payload = bytes(packet_ip.payload)

            opcode = (payload[0] & 0b11111000) >> 3
            opcodes.append(opcode)
    return opcodes

def flag_openvpn_in_capture(filename):
    opcodes = []
    packets = rdpcap(filename)
    conversations = group_conversations(packets)

    results = {}
    for key, packets_in_conversation in conversations.items():
        print(key)
        opcodes = find_opcodes(packets_in_conversation)
        print(opcodes)
        results[key] = opcode_algorithm.opcode_fingerprinting(opcodes)
    return results

def main(argv):
    files = [
        "pcap-dumps/mullvad-ovpn-bridge-mode.pcap",
        "pcap-dumps/synthesized-openvpn-server-dump.pcap",
        "pcap-dumps/non-vpn.pcap"
    ]  

    for file in files:
        results = flag_openvpn_in_capture(file)

        for (ip1, ip2), result in results:
            print(f"conversation between {ip1} and {ip2} Flagged: {result}")

if __name__ == "__main__":
    main(sys.argv)
