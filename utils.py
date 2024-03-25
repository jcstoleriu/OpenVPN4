from scapy.layers.inet import UDP, IP, TCP
import tqdm

def get_connection_key(packet):
    key = None
    if IP in packet:
        packet_ip = packet[IP]

        port_src = 0
        port_dst = 0
        if UDP in packet:
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
        if TCP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

        key = [(packet_ip.src, port_src), (packet_ip.dst, port_dst)]
        key.sort(key=lambda k : k[0] + str(k[1]))
        key = tuple(key)

    return key

def print_summary(file, conversations, items, printer=lambda x : print(x), algorithm_labels=["opcode", "ACK"]):
    printer("")
    printer(f"############ Summary for file {file} ############")
    printer(f"Found {len(conversations)} conversations")
    for i, algorithm_label in enumerate(algorithm_labels):
        printer(f"{len([v for v in items if v[1][i]])} flagged as VPN by the {algorithm_label} algorithm")
    printer(f"################################################")
    printer("")

def group_conversations(packets, progressbar=False):
    conversations = {}
    ids = {}

    packets_iterator = packets
    if progressbar:
        packets_iterator = tqdm.tqdm(packets)
    for i, packet in enumerate(packets_iterator):
        key = get_connection_key(packet)
        if key is None:
            continue
        if not key in conversations:
            conversations[key] = []
            ids[key] = i
        conversations[key].append(packet)
    
    conversations_with_id = {ids[key]:v for key, v in conversations.items()}
    return conversations, conversations_with_id