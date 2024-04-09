from scapy.all import PcapReader
from scapy.layers.inet import UDP, TCP
from src.utils import group_conversations, print_summary

def fingerprint_packets(file, conversations=None, params={}, printer=lambda x:x):
    if conversations is None:
        packets = PcapReader(file)
        conversations = group_conversations(packets)

    results = {}
    for key, packets_in_conversation in conversations.items():
        result = ack_fingerprinting(packets_in_conversation, params=params)

        results[key] = result

    print_summary(file, conversations, [(k,tuple([v])) for k,v in results.items()], printer=printer, algorithm_labels=["ACK"])

    return results

MOD_4_IMPROVEMENT_KEY = "mod_4_improvement"
def similar_to_ack_candidate(packet, ack_candidate, params=None):
    if params is None: params = {}
    if not (UDP in packet or TCP in packet) or ack_candidate is None:
        return False
    
    ack_candiate_size = len(ack_candidate)
    packet_size = len(packet)

    if MOD_4_IMPROVEMENT_KEY in params and params[MOD_4_IMPROVEMENT_KEY] and ack_candiate_size % 4 == packet_size % 4:
        return False

    # Check if packet is within a +- 4 * 4 byte range of the ack candidate
    return ack_candiate_size - 16 <= packet_size <= ack_candiate_size + 16

def ack_fingerprinting(packets, params={}):
    ack_candidate = None
    i = 0
    for packet in packets:
        payload = None

        if UDP in packet:
            packet_udp:UDP = packet[UDP]
            payload = bytes(packet_udp.payload.original)
        if TCP in packet:
            packet_tcp:TCP = packet[TCP]
            payload = bytes(packet_tcp.payload.original)

        if i < 2:
            i += 1
            continue

        if payload is None or not len(payload) in range(22, 55):
            continue
        

        # This is now our candidate for an ACK package
        ack_candidate = packet
        break

    # no ack candidate found
    if ack_candidate is None:
        return False

    # Group packets in bins of 10
    bins = []
    for i in range(0, len(packets), 10):
        if i == 0:
            bins.append(packets[2:10])
        else:
            bins.append(packets[i:i+10])

    # For each bin count the number of packets that are similar to the ack candidate
    histogram = [len(list(filter(lambda p: similar_to_ack_candidate(p, ack_candidate, params=params), bin))) for bin in bins]

    if len(histogram) < 5:
        return False

    if histogram[0] < 1 or histogram[0] > 3:
        return False
    if histogram[1] < 2 or histogram[1] > 5:
        return False
    for i in range(2,5):
        if histogram[i] > 5:
            return False
    for i in range(5, len(histogram)):
        if histogram[i] > 1:
            return False

    return True