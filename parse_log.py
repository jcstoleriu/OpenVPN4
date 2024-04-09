import re as regex
'''
Parsese the logfile which has repeated contents like below:

Running experiment 'VPN Detection Opcode' with algorithm opcode (1 of 4 experiments)

############ Summary for file ../datasets/ISCXVPN2016/PCAPs/VPN-PCAPs-02/vpn_sftp_B.pcap ############
Found 13 conversations
0 flagged as VPN by the opcode algorithm
################################################

...

And returns a dictionary like below:
{
    'algorithm': 'VPN Detection Opcode',
    'file': '../datasets/ISCXVPN2016/PCAPs/VPN-PCAPs-02/vpn_sftp_B.pcap',
    'conversations': 13,
    'flagged': 0
}

'''
def parse(logfile):
    lines = '\n'.join(logfile.readlines())
    experiments = regex.findall(r"Running experiment '(.+)'", lines)
    files = regex.findall(r"Summary for file (.+) ", lines)
    conversations = regex.findall(r"Found (\d+) conversations", lines)
    flagged = regex.findall(r"(\d+) flagged as VPN by ", lines)
    
    results = []
    for experiment, file, conversation, flag in zip(experiments, files, conversations, flagged):
        results.append({
            'algorithm': experiment,
            'file': file,
            'conversations': int(conversation),
            'flagged': int(flag)
        })

    return results


if __name__ == '__main__':
    print(parse('experiments/VNAT_VPN-NonVPN_Network_Application_Traffic_Dataset_part1.log'))