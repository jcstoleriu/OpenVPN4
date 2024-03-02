from scapy.all import *
from scapy.layers.tls.record import TLS

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


if __name__ == "__main__":
    load_layer("tls")
    file = rdpcap('VPN-PCAPS-01/vpn_aim_chat1a.pcap')
    for packet in file:
        if TLS in packet:
            print(packet[TLS].msg)