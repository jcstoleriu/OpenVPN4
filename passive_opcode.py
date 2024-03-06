from scapy.all import rdpcap
from scapy.layers.inet import UDP, IP
# import cryptography
import opcode_algorithm
import sys

'''
Structure of encrypted TLS data depends on negotiated cipher suite
- AES_GCM (most common in the pcaps) => starts with 8 byte nonce NOT part of encrypted data
- CBC modes (common in chat files) => starts with 16 byte IV also NOT part of encrypted data
Sometimes this is not the case. Not sure why.
ref:
https://security.stackexchange.com/questions/187924/tls1-2-aes-128-cbc-encrypted-data-size
https://security.stackexchange.com/questions/136180/tls-1-2-and-enable-only-aead-ciphers-suite-list
https://security.stackexchange.com/questions/54466/in-ssl-tls-what-part-of-a-data-packet-is-encrypted-and-authenticated
'''

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

def main(argv):
    file = rdpcap('openvpn-server/dump.pcap')

    conversations = group_conversations(file)

    for (ip1, ip2), packets in conversations.items():
        opcodes = find_opcodes(packets)

        print(opcode_algorithm.opcode_fingerprinting(opcodes, len(opcodes)))


if __name__ == "__main__":
    main(sys.argv)
