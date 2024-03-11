import scapy.all as scapy
from scapy.layers.tls.record import TLS
import matplotlib.pyplot as plt
import cryptography
from scapy.packet import Raw


def similar_to_ack_candidate(packet, ack_candidate):
    if scapy.UDP not in packet:
        return False
    if TLS in packet:
        return False
    
    ack_candiate_size = len(ack_candidate)
    packet_size = len(packet[scapy.UDP])

    print(f"Packet size: {packet_size} \t ack candidate size: {ack_candiate_size}")

    # Check if packet is within a +- 4 * 4 byte range of the ack candidate
    return ack_candiate_size - 16 <= packet_size <= ack_candiate_size + 16
    

def ack_fingerprinting(packets):
    ack_candidate = None
    for packet in packets[2:]:
        if scapy.UDP not in packet:
            continue
            # Check if there is a TLS layer

        # TODO: This is not reliable... Unfortunately the TLS layer is not always detected even though it is there
        if packet.haslayer(TLS):
            continue

        print(TLS(packet[Raw].load))
        packet_udp:scapy.UDP = packet[scapy.UDP]
        # This is now our candidate for an ACK package
        ack_candidate = packet_udp
        print(f"Found ack candidate: {ack_candidate}")
        break

    # Group packets in bins of 10
    bins = []
    for i in range(0, len(packets), 10):
        bins.append(packets[i:i+10])

    print(f"Found {len(bins)} bins")

    # For each bin count the number of packets that are similar to the ack candidate
    histogram = [len(list(filter(lambda p: similar_to_ack_candidate(p, ack_candidate), bin))) for bin in bins]

    #plt.plot(histogram)
    #plt.show()

    




