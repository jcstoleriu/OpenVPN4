from scapy.packet import Packet
from scapy.fields import IntField, ShortField, BitField
from scapy.compat import orb

from scapy.packet import Packet
from scapy.fields import BitField, IntField, LongField, ByteField, StrLenField, FieldListField, LenField, ConditionalField
from scapy.all import bind_layers
from scapy.layers.inet import UDP

class OpenVPN(Packet):
    name = "OpenVPN"
    fields_desc = [
                BitField("opcode", 0, 5),
                BitField("keyid", 0, 3),
                LongField("own_session_id", 0),
                ConditionalField(StrLenField("hmac", "", length_from=lambda pkt: pkt._calc_hmac_len()), lambda pkt: pkt.has_hmac),
                ConditionalField(IntField("replay_packet_id", 0), lambda pkt: pkt.has_hmac),
                ConditionalField(IntField("net_time", 0), lambda pkt: pkt.has_hmac),
                ByteField("acked_pktid_len", 0),
                FieldListField("acked_pktid_list", [], IntField("", 0), length_from=lambda pkt: pkt._calc_acked_pktid_list_len()),
                # # the peer session id is only present if the acked_pktid_len is > 0
                ConditionalField(LongField("remote_session_id", 0), lambda pkt: pkt.acked_pktid_len > 0),
                ConditionalField(IntField("message_packet_id", 0), lambda pkt: pkt.has_packet_id()),
                # StrLenField("payload", "", length_from=lambda pkt: len(pkt))
            ]
    
    has_hmac = False

    def check_for_hmac(self, bytes: bytes) -> bool:
        # if the first 4 bits of the hmac field are 0 then the packet has no HMAC
        # this is the 9th byte in the packet
        count = 0
        for i in range(9, 13):
            if orb(bytes[i]) == 0:
                count += 1
                
        return count <= 1

    def has_packet_id(self) -> bool:
        return self.opcode in [4, 7, 8]

    def _calc_hmac_len(self):
        # Calculate HMAC length based on the number of bytes specified in the specification (8-32)
        # return max(min(len(self.hmac), 32), 8)
        return 20
    
    def is_valid_packet(self) -> bool:
        return len(self.original) >= self._min_length()
    
    # min length
    def _min_length(self):
        # Calculate minimum length required for an OpenVPN packet
        min_len = 1 + 8  # opcode (5 bits) + keyid (3 bits) + own_session_id (64 bits)
        if self.has_hmac:
            min_len += self._calc_hmac_len() + 4 + 4  # hmac + replay_packet_id (32 bits) + net_time (32 bits)
        min_len += 1 # acked_pktid_len (8 bits)

        if self.acked_pktid_len > 0:
            min_len += self._calc_acked_pktid_list_len()  # acked_pktid_list
            min_len += 8  # remote_session_id (64 bits)

        if self.has_packet_id():
            min_len += 4  # packet_id (32 bits)
        return min_len

    def _calc_acked_pktid_list_len(self):
        # Calculate the length of acked_pktid_list based on acked_pktid_len
        result = self.acked_pktid_len * 4
        return result
    
    def pre_dissect(self, s: bytes) -> bytes:
        # calc if there is a hmac
        self.has_hmac = self.check_for_hmac(s)

        return super().pre_dissect(s)

# Register the new protocol with Scapy
bind_layers(UDP, OpenVPN, dport=1194)
bind_layers(UDP, OpenVPN, sport=1194)