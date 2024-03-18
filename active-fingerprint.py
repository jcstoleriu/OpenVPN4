import struct
import random 
import socket

def create_openvpn_payload(pkt_len, opcode, key_id, session_id, hmac):
    """
    Create an OpenVPN payload
    :param pkt_len: The length of the packet (16 bits)
    :param opcode: The opcode of the packet (5 bits)
    :param key_id: The key ID (3 bits)
    :param session_id: The session ID (64 bits)
    :param hmac: The invalid hmac (32? bits)
    """
    opcode_and_key_id = (opcode << 3) | key_id
    return struct.pack('!HBQI', pkt_len, opcode_and_key_id, session_id, hmac)


def drops_connection_immediately(server_ip: str, server_port: int, payload: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((server_ip, server_port))
    s.send(payload)

    # Send data and check if connection has been closed
    try:
        data = s.recv(1024)
        if not data:
            return True
    except socket.timeout:
        return False

def fingerprint(server_ip: str, server_port: int):
    probe_1 = create_openvpn_payload(13, 7, 0, random.getrandbits(64), 0)
    probe_2 = create_openvpn_payload(14, 7, 0, random.getrandbits(64), 0)

    dropped_1 = drops_connection_immediately(server_ip, server_port, probe_1)
    dropped_2 = drops_connection_immediately(server_ip, server_port, probe_2)

    return dropped_1 and not dropped_2

print(fingerprint("10.3.0.222", 1194))