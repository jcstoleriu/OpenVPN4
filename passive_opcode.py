from scapy.all import rdpcap
from scapy.layers.inet import UDP
# import cryptography
import opcode_algorithm

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

N = 100

if __name__ == "__main__":
    # load_layer("tls")
    opcodes = []
    file = rdpcap('openvpn-server/dump.pcap')
    for packet in file:
        if UDP in packet:
            # application data packets
            packet_udp:UDP = packet[UDP]
            payload = bytes(packet_udp.payload)
            # print(payload)
            opcode = (payload[0] & 0b11111000) >> 3
            print(opcode)
            opcodes.append(opcode)
    print(opcode_algorithm.opcode_fingerprinting(opcodes, len(opcodes)))
