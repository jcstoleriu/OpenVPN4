import struct
import random 
import socket
import argparse

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
        else:
            # print(f"Received data: {data}")
            return False
    except socket.timeout:
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    
def responds_with_rst(server_ip: str, server_port: int, payload: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((server_ip, server_port))
    s.send(payload)
    try:
        s.recv(1)
    except ConnectionResetError:
        return True
    return False


def fingerprint(server_ip: str, server_port: int):
    # Probe 1: connection will be immediately dropped by the server because of the invalid hmac
    probe_1 = create_openvpn_payload(13, 7, 0, random.getrandbits(64), 0)
    # Probe 2: conneciton will stay open because the openvpn server expects one more byte
    probe_2 = create_openvpn_payload(14, 7, 0, random.getrandbits(64), 0)
    # Probe 3: connection will be immediately dropped by the server because the length is over max_len=1627
    probe_3 = create_openvpn_payload(1628, 7, 0, random.getrandbits(64), 0)
    # Probe 4: the vast majority of OpenVPN servers have a RST threshold around 1550-1660 bytes
    probe_4 = random.getrandbits(2000 * 8).to_bytes(2000, byteorder='big')

    dropped_1 = drops_connection_immediately(server_ip, server_port, probe_1)
    dropped_2 = drops_connection_immediately(server_ip, server_port, probe_2)
    dropped_3 = drops_connection_immediately(server_ip, server_port, probe_3)
    connection_reset = responds_with_rst(server_ip, server_port, probe_4)

    print(f"Base Probe 1 (immediately dropped): \t\t{dropped_1}")
    print(f"Base Probe 2 (not immediately dropped): \t{not dropped_2}")
    print(f"Length Validaiton (immediately dropped): \t{dropped_3}")
    print(f"RST Threshold (respopnded with RST): \t\t{connection_reset}")

    return (dropped_1 and not dropped_2) and dropped_3 and connection_reset

def main():
    parser = argparse.ArgumentParser(description="Active fingerprinting of a OpenVPN server")
    parser.add_argument("server_ip", help="The IP of the OpenVPN server")
    parser.add_argument("server_port", type=int, help="The port of the OpenVPN server")

    args = parser.parse_args()

    fingerprint(args.server_ip, args.server_port)
    

if __name__ == "__main__":
    main()