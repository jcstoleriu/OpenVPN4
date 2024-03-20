from scapy.layers.inet import UDP, TCP
from scapy.all import rdpcap
from utils import group_conversations

# fingerprint packets in pcap files
def fingerprint_packets(file, conversations=None, params={}):
    if conversations is None:
        packets = rdpcap(file)
        conversations, conversations_with_id = group_conversations(packets)

    results = {}
    for key, packets_in_conversation in conversations.items():
        opcodes = find_opcodes(packets_in_conversation)
        opcode_result = opcode_fingerprinting(opcodes, params=params)

        results[key] = opcode_result

    return results

def find_opcodes(packets):
    opcodes = []
    for packet in packets:
        payload = None
        if UDP in packet:
            # application data packets
            packet_udp:UDP = packet[UDP]
            payload = bytes(packet_udp.payload)
        if TCP in packet:
            packet_tcp:TCP = packet[TCP]
            payload = bytes(packet_tcp.payload)

        if payload is None or len(payload) < 1:
            continue

        opcode = (payload[0] & 0b11111000) >> 3
        opcodes.append(opcode)
    return opcodes

XOR_OPCODES_KEY = "xor_opcodes"
def opcode_fingerprinting(opcodes, params=None):
    if params is None:
        params = {}
    # opcodes is a list of different opcodes
    if len(opcodes) < 2:
        return False
    CR=opcodes[0]
    SR=opcodes[1]

    if not CR ^ SR in [1^2, 7^8] and XOR_OPCODES_KEY in params:
        return False

    OCSet=set([SR,CR])
    for opcode in opcodes:
        if opcode in [CR, SR] and len(OCSet)>=4:
            return False
        OCSet.add(opcode)
    return 4 <= len(OCSet) <= 10
