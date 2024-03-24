import scapy.all as scapy
from scapy.all import PcapReader
from scapy.layers.tls.record import TLS
from scapy.layers.inet import UDP, IP
import matplotlib.pyplot as plt
import cryptography
from scapy.packet import Raw
from openvpn_header import OpenVPN
from utils import group_conversations, print_summary

def fingerprint_packets(file, conversations=None, params={}, printer=lambda x:x):
    if conversations is None:
        packets = PcapReader(file)
        conversations, conversations_with_id = group_conversations(packets)

    results = {}
    for key, packets_in_conversation in conversations.items():
        result = ack_fingerprinting(packets_in_conversation, params=params)

        results[key] = result

    print_summary(file, conversations, [(k,(False, v)) for k,v in results.items()], printer=printer)

    return results

def similar_to_ack_candidate(packet, ack_candidate):
    if scapy.UDP not in packet or ack_candidate is None:
        return False
    
    ack_candiate_size = len(ack_candidate)
    packet_size = len(packet)

    # Check if packet is within a +- 4 * 4 byte range of the ack candidate
    return ack_candiate_size - 16 <= packet_size <= ack_candiate_size + 16

def ack_fingerprinting(packets, params={}):
    ack_candidate = None
    i = 0
    for packet in packets:
        if UDP not in packet:
            continue
        # Check if there is a TLS layer
        packet_udp:UDP = packet[UDP]

        # packet_openvpn: OpenVPN = packet_udp.payload

        # if not OpenVPN in packet_openvpn:
        #     # TODO: fix this. For packets that are not openvpn some errors occur. currently we just ignore packets like this
        #     try:
        #         packet_openvpn = OpenVPN(packet_openvpn.original)
        #     except Exception:
        #         continue

        # if not packet_openvpn.is_valid_packet() or len(packet_openvpn.payload) > 0:
        #     continue
        if not len(packet_udp.payload.original) in range(22, 55):
            continue
        
        if i < 2:
            i += 1
            continue

        packet_udp:scapy.UDP = packet[scapy.UDP]
        # This is now our candidate for an ACK package
        ack_candidate = packet
        # print(f"Found ack candidate: {ack_candidate[IP].id} {len(ack_candidate)}")
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

    # print(f"Found {len(bins)} bins")

    # For each bin count the number of packets that are similar to the ack candidate
    histogram = [len(list(filter(lambda p: similar_to_ack_candidate(p, ack_candidate), bin))) for bin in bins]

    # plt.plot(histogram[:10])
    # plt.show()

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
        

    # plt.plot(histogram[:10])
    # plt.show()

    return True

    




