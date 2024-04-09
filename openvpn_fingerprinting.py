from scapy.all import PcapReader
from src import opcode_algorithm, ack_algorithm
from src.utils import group_conversations, print_summary
import argparse
import active_fingerprinting

def flag_openvpn_in_capture(filename, params={}, use_active_fingerprinting=False):
    packets = PcapReader(filename)
    print(f"Reading file {filename}...")
    conversations = group_conversations(packets, progressbar=True)
    results_opcode = opcode_algorithm.fingerprint_packets(filename, conversations=conversations, params=params)
    results_ack = ack_algorithm.fingerprint_packets(filename, conversations=conversations, params=params)

    results = {}
    for key, _ in conversations.items():
        opcode_result = results_opcode[key]
        ack_result = results_ack[key]
        
        active_fingerprinting_result = None
        if use_active_fingerprinting and (opcode_result or ack_result):
            c1_result = active_fingerprinting.fingerprint(*key[0])
            c2_result = active_fingerprinting.fingerprint(*key[1])
            active_fingerprinting_result = (c1_result, c2_result)

        results[key] = (opcode_result, ack_result, active_fingerprinting_result)

    return results, conversations


def main():
    files = [
        "docker-pcaps/udp.pcap",
        "docker-pcaps/tcp.pcap",
        "docker-pcaps/udp-tls.pcap",
        "docker-pcaps/tcp-tls.pcap",
        "pcap-dumps/synthesized-openvpn-server-dump.pcap",
    ]

    parser = argparse.ArgumentParser(description="Flag OpenVPN connections in a pcap file")
    parser.add_argument("files", nargs="*", default=files, help="The pcap files to analyze")
    parser.add_argument("-o", action="store_true", help="Use XOR Optimization in the opcode algorithm")
    parser.add_argument("--active-fingerprinting", action="store_true", help="Use active fingerprinting (default: False)")

    args = parser.parse_args()

    params = {opcode_algorithm.XOR_OPCODES_KEY: args.o}
    for file in args.files:
        results, conversations = flag_openvpn_in_capture(file, params=params)

        items = list(results.items())
        items.sort(key=lambda k : sum([int(v) for v in k[1][:2]]))
        for (ip1, ip2), result in items:
            print(f"\nconversation between {ip1} and {ip2}")
            
            print(f"Opcode algorithm flag result: {result[0]}")
            print(f"ACK algorithm flag result: {result[1]}")

            active_fingerprinting_result = result[2]
            if not active_fingerprinting_result is None:
                if active_fingerprinting_result[0]:
                    print(f"{ip1} was flagged as VPN by the active fingerprinting algorithm!")
                if active_fingerprinting_result[1]:
                    print(f"{ip2} was flagged as VPN by the active fingerprinting algorithm!")
                if not (active_fingerprinting_result[0] or active_fingerprinting_result[1]):
                    print("No VPN flag by the active fingerprinting algorithm")

        print_summary(file, conversations, items)

if __name__ == "__main__":
    main()
