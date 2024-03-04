from scapy.all import rdpcap
from scapy.layers.inet import UDP
import opcode_algorithm


def flag_openvpn_in_capture(filename):
    opcodes = []
    file = rdpcap(filename)
    for packet in file:
        if UDP in packet:
            # application data packets
            packet_udp:UDP = packet[UDP]
            payload = bytes(packet_udp.payload)
            opcode = (payload[0] & 0b11111000) >> 3
            opcodes.append(opcode)
    return opcode_algorithm.opcode_fingerprinting(opcodes)


if __name__ == "__main__":
    print("Flagged: ", flag_openvpn_in_capture("pcap-dumps/mullvad-ovpn-bridge-mode.pcap"))
    print("Flagged: ", flag_openvpn_in_capture("pcap-dumps/synthesized-openvpn-server-dump.pcap"))
    print("Flagged: ", flag_openvpn_in_capture("pcap-dumps/non-vpn.pcap"))
