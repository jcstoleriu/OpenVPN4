from scapy.packet import Packet
from scapy.fields import IntField, ShortField, BitField
from scapy.compat import orb

from scapy.packet import Packet
from scapy.fields import BitField, IntField, LongField, ByteField, StrLenField, FieldListField, LenField
from scapy.all import bind_layers
from scapy.layers.inet import UDP

class OpenVPNMinimal(Packet):
    name = "OpenVPNMinimal"
    fields_desc = [
                BitField("opcode", 0, 5),
                BitField("keyid", 0, 3),
                LongField("own_session_id", 0),
                ByteField("acked_pktid_len", 0),
                FieldListField("acked_pktid_list", [], IntField("", 0), length_from=lambda pkt: pkt._calc_acked_pktid_list_len()),
                StrLenField("remote_session_id", "", length_from=lambda pkt: 8 if pkt.acked_pktid_len > 0 else 0),
                StrLenField("message_packet_id", "", length_from=lambda pkt: 4 if pkt.opcode in [7, 8] else 0),
                StrLenField("payload", "", length_from=lambda pkt,pay: len(pay))
            ]
    def _calc_hmac_len(self):
        # Calculate HMAC length based on the number of bytes specified in the specification (8-32)
        # return max(min(len(self.hmac), 32), 8)
        return 20
        
    def _calc_acked_pktid_list_len(self):
        # Calculate the length of acked_pktid_list based on acked_pktid_len
        return self.acked_pktid_len * 4

class OpenVPN(OpenVPNMinimal):
    name = "OpenVPN"
    fields_desc = [
            BitField("opcode", 0, 5),
            BitField("keyid", 0, 3),
            LongField("own_session_id", 0),
            StrLenField("hmac", "", length_from=lambda pkt: pkt._calc_hmac_len()),
            IntField("replay_packet_id", 0),
            IntField("net_time", 0),
            ByteField("acked_pktid_len", 0),
            FieldListField("acked_pktid_list", [], IntField("", 0), length_from=lambda pkt: pkt._calc_acked_pktid_list_len()),
            # the peer session id is only present if the acked_pktid_len is > 0
            StrLenField("remote_session_id", "", length_from=lambda pkt: 8 if pkt.acked_pktid_len > 0 else 0),
            StrLenField("message_packet_id", "", length_from=lambda pkt: 4 if pkt.opcode in [7, 8] else 0),
            StrLenField("payload", "", length_from=lambda pkt,pay: len(pay))
        ]

# Register the new protocol with Scapy
bind_layers(UDP, OpenVPN, dport=1194)
bind_layers(UDP, OpenVPN, sport=1194)
bind_layers(UDP, OpenVPNMinimal, dport=1302)
bind_layers(UDP, OpenVPNMinimal, sport=1302)