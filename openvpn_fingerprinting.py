from scapy.all import rdpcap
from scapy.layers.inet import UDP, IP, TCP
# import cryptography
import opcode_algorithm
import ack_algorithm
from utils import group_conversations
import sys, tqdm


def flag_openvpn_in_capture(filename):
    packets = rdpcap(filename)
    conversations, conversations_with_id = group_conversations(packets)
    results_opcode = opcode_algorithm.fingerprint_packets(filename, conversations=conversations)
    results_ack = ack_algorithm.fingerprint_packets(filename, conversations=conversations)

    results = {}
    for key, packets_in_conversation in conversations.items():
        results[key] = (results_opcode[key], results_ack[key])

    return results, conversations

def main(argv):
    files = [
        "pcap-dumps/mullvad-ovpn-bridge-mode.pcap",
        "pcap-dumps/synthesized-openvpn-server-dump.pcap",
        "pcap-dumps/non-vpn.pcap",
    ]

    if len(argv) > 1:
        files = argv[1:]

    for file in files:
        results, conversations = flag_openvpn_in_capture(file)

        items = list(results.items())
        items.sort(key=lambda k : sum([int(v) for v in k[1]]))
        for (ip1, ip2), result in items:
            print(f"Flagged: {result[0]}\tIn conversation between {ip1} and {ip2}")
            
            print(f"ACK flag result: {result[1]}")
        
        print(f"\n############ Summary for file {file} ############")
        print(f"Found {len(conversations)} conversations")
        print(f"{len([v for v in items if v[1][0]])} flagged as VPN by the opcode algorithm")
        print(f"{len([v for v in items if v[1][1]])} flagged as VPN by the ACK algorithm")
        print(f"################################################\n")

if __name__ == "__main__":
    main(sys.argv)
