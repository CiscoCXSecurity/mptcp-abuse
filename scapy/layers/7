## This file defines and implements the MPTCP options
# It is imported by inet.py. It has not been integrated in inet.py for clarity
# only.
from scapy.packet import *
from scapy.fields import *
#from scapy.layers.inet import IP
#if conf.ipv6_enabled:
#    from scapy.layers.inet6 import IPv6
#    from scapy.layers.inet6 import IP6Field #to support IPv6 addresses
from scapy.config import conf
#from scapy.layers.inet import tcpoption, _tcpoption_hdr




#############################
# mpTCP options definitions #
#############################

MPTCP_subtypes = { 
        0x0: 'MP_CAPABLE',
        0x1: 'MP_JOIN',
        0x2: 'DSS',
        0x3: 'ADD_ADDR',
        0x4: 'REMOVE_ADDR',
        0x5: 'MP_PRIO',
        0x6: 'MP_FAIL'}



class Sha1Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "IIIII")
    def addfield(self, pkt, s, val):
        """Add an internal value to a string, adaptation for 5-parts value"""
        #print "I2M: ",self.i2m(pkt,val)
        return s+struct.pack(self.fmt, *self.i2m(pkt,val))
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt,s[:self.sz])[0:5])
    def m2i(self, pkt, x):
        """Convert list of 32bits integers to 160bits value"""
        return sum([c << (4-e)*32 for e,c in enumerate(x)])
    def i2m(self, pkt, x):
        """Convert 160bits value to list of 32bits integers"""
        return [x>>e*32 & (1<<32)-1 for e in xrange(4,-1,-1)]
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

class _MP_HDR(Packet):
    fields_desc = [ByteField("length", 8),
                    BitEnumField("subtype", 0, 4, MPTCP_subtypes), ]
#    fields_desc = [
 #                   BitEnumField("subsubtype", 192, 12, MPTCP_subtypes), ]

class MPOption(Packet):
    """TCP option for multipath support, with no known subtype. This
    instanciates mptcp inherited subtypes by introspection."""
    name = "Multipath TCP option"
    subsubtype = 0
    fields_desc = [ _MP_HDR,
                    StrLenField("value", "",length_from=lambda
                            pkt:pkt.length-2) ]

    def extract_padding(self, p):
        return "",p

    registered_mptcp_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_mptcp_options[(cls.length.default<<4)+cls.subtype.default] = cls
    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            #print pkt
            opt = ord(pkt[0])<<4 # subsubtype is the first byte + 4bits from 2nd byte
            opt += ord(pkt[1])>>4
            if opt in cls.registered_mptcp_options:
                return cls.registered_mptcp_options[opt]
        return cls


class MPTCP_CapableSYN(MPOption):
# SYN and SYNACK
    name = "Multipath TCP capability"
    subtype = 0
    subsubtype = 12<<4+0

    fields_desc = [ ByteField("length", 12),
                    BitEnumField("subtype", 0, 4, MPTCP_subtypes),
                    BitField("version", 0, 4), # 0 is the current (draft) default version 
                    BitField("checksum_req", 0, 1),
                    BitField("reserved",0, 6),
                    BitField("hmac_sha1", 1, 1),
                    XLongField("snd_key",None),]

MPTCP_CapableSYNACK = MPTCP_CapableSYN


class MPTCP_CapableACK(MPOption):
    name = "Multipath TCP capability"
    subtype = 0
    subsubtype = 20<<4+0
    fields_desc = [ ByteField("length", 20),
                    BitEnumField("subtype", 0, 4, MPTCP_subtypes),
                    BitField("version", 0, 4), # 0 is the current (draft) default version 
                    BitField("checksum_req", 0, 1),
                    BitField("reserved",0, 6),
                    BitField("hmac_sha1", 1, 1),
                    XLongField("snd_key",None),
                    XLongField("rcv_key",None),]



class MPTCP_JoinSYN(MPOption):
    name = "Multipath TCP join"
    subtype = 1
    subsubtype = 12<<4+1
    fields_desc = [ ByteField("length", 12),
                    BitEnumField("subtype", 1, 4, MPTCP_subtypes),
                    BitField("reserved_flags", 0, 3),
                    BitField("backup_flow", 0, 1),
                    ByteField("addr_id",0),
                    XIntField("rcv_token", 0),
                    XIntField("snd_nonce", RandInt()),
                    ]

class MPTCP_JoinSYNACK(MPOption):
    name = "Multipath TCP join"
    subtype = 1
    subsubtype = 16<<4+1
    fields_desc = [ ByteField("length", 16),
                    BitEnumField("subtype", 1, 4, MPTCP_subtypes),
                    BitField("reserved_flags", 0, 3),
                    BitField("backup_flow", 0, 1),
                    ByteField("addr_id",0),
                    XLongField("snd_mac64", 0),
                    XIntField("snd_nonce", RandInt()),]

class MPTCP_JoinACK(MPOption):
    name = "Multipath TCP join"
    subtype = 1
    subsubtype = 24<<4+1
    fields_desc = [ ByteField("length", 24),
                    BitEnumField("subtype", 1, 4, MPTCP_subtypes),
                    BitField("reserved_flags", 0, 12),
                    Sha1Field("snd_mac", 0),]



class _DSS_HDR(Packet):
    fields_desc = [BitEnumField("subtype", 2, 4, MPTCP_subtypes),
            BitField("reserved", 0, 7),
            ]
            
#            BitField("F", 0, 1), # easier to refer than flagsfield
#            BitField("m", 0, 1), # data seq is 8 bytes-long (not 4)
#            BitField("M", 0, 1), # dataseq, subflow seq, datalen, csum present
#            BitField("a", 0, 1), # data ack is 8 bytes-long (not 4)
#            BitField("A", 0, 1), # data ack present


#class MPTCP_DSS(Packet):
#    name = "Multipath TCP Data Sequence Signal"
#    subtype = 2
#
#    fields_desc = [ _DSS_HDR, ]
#
#    def post_build(self, p, pay):
#        print "####### POST_BUILD"

# XXX might be useful
def contains_flag(l, flag):
    """With l being the flag field value, flag being the flag's position in the
    field (counting from the right, starting at 0)"""
    l = l >> flag
    return l % 2 == 1

def mptcp_dss_contains_flag(l, flag):
    flags = "AaMmF"
    return contains_flag(l, flags.index(flag))

def tcp_contains_flag(l, flag):
    flags = "FSRPAUEC"
    return contains_flag(l, flags.index(flag))

flagIn = mptcp_dss_contains_flag


class MPTCP_DSS_Ack(MPOption):
    """Composed of a 32bits ack without checksum"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 8<<4+2
    fields_desc = [ ByteField("length", 8),
                    _DSS_HDR,
                    FlagsField("flags", "A", 5, "AaMmF"),
                    IntField("data_ack", 0),]

                    
class MPTCP_DSS_Ack64(MPOption):
    """Composed of a 64bits ack without checksum"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 12<<4+2
    fields_desc = [ ByteField("length", 12),
                    _DSS_HDR,
                    FlagsField("flags", "aA", 5, "AaMmF"),
                    LongField("data_ack", 0),]

class MPTCP_DSS_Map(MPOption):
    """Composed of a short mapping"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 14<<4+2
    fields_desc = [ ByteField("length", 16),
                    _DSS_HDR,
                    FlagsField("flags", "M", 5, "AaMmF"),
                    IntField("dsn", 0),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),
                    XShortField("checksum", 0),]

class MPTCP_DSS_MapCsum(MPOption):
    """Composed of a short mapping"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 16<<4+2
    fields_desc = [ ByteField("length", 16),
                    _DSS_HDR,
                    FlagsField("flags", "M", 5, "AaMmF"),
                    IntField("dsn", 0),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),
                    XShortField("checksum", 0),]

class MPTCP_DSS_Map64_AckMap(MPOption):
    """Composed of a mapping with 64bits seq OR of the combination of an Ack
    and a short mapping""" 
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 18<<4+2
    fields_desc = [ ByteField("length", 20),
                    _DSS_HDR,
                    FlagsField("flags", "AM", 5, "AaMmF"),
                    ConditionalField(IntField("data_ack", 0),
                        lambda p: not flagIn(p.flags,"a") and flagIn(p.flags,"A")),
                    ConditionalField(LongField("dsn", 0),
                        lambda p: flagIn(p.flags,"m") and flagIn(p.flags,"M")),
                    ConditionalField(IntField("dsn", 0),
                        lambda p: not flagIn(p.flags,"m") and flagIn(p.flags,"M")),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),]

class MPTCP_DSS_Map64_AckMapCsum(MPOption):
    """Composed of a mapping with 64bits seq OR of the combination of an Ack
    and a short mapping""" 
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 20<<4+2
    fields_desc = [ ByteField("length", 20),
                    _DSS_HDR,
                    FlagsField("flags", "AM", 5, "AaMmF"),
                    ConditionalField(IntField("data_ack", 0),
                        lambda p: not flagIn(p.flags,"a") and flagIn(p.flags,"A")),
                    ConditionalField(LongField("dsn", 0),
                        lambda p: flagIn(p.flags,"m") and flagIn(p.flags,"M")),
                    ConditionalField(IntField("dsn", 0),
                        lambda p: not flagIn(p.flags,"m") and flagIn(p.flags,"M")),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),
                    XShortField("checksum", 0),]

MPTCP_DSS_AckMapCsum = MPTCP_DSS_Map64_AckMapCsum
MPTCP_DSS_Map64Csum = MPTCP_DSS_Map64_AckMapCsum

class MPTCP_DSS_Ack64Map(MPOption):
    """Composed of a 64bits ack and a mapping"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 22<<4+2
    fields_desc = [ ByteField("length", 24),
                    _DSS_HDR,
                    FlagsField("flags", "aAM", 5, "AaMmF"),
                    LongField("data_ack", 0),
                    IntField("dsn", 0),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),]

class MPTCP_DSS_Ack64Map_AckMap64Csum(MPOption):
    """Composed of a 64bits ack and a mapping"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 24<<4+2
    fields_desc = [ ByteField("length", 24),
                    _DSS_HDR,
                    FlagsField("flags", "aAM", 5, "AaMmF"),
                    ConditionalField(IntField("data_ack", 0),
                        lambda p: not flagIn(p.flags,"a") and flagIn(p.flags,"A")),
                    ConditionalField(LongField("data_ack", 0),
                        lambda p: flagIn(p.flags,"a") and flagIn(p.flags,"A")),
                    ConditionalField(LongField("dsn", 0),
                        lambda p: flagIn(p.flags,"m") and flagIn(p.flags,"M")),
                    ConditionalField(IntField("dsn", 0),
                        lambda p: not flagIn(p.flags,"m") and flagIn(p.flags,"M")),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),
                    XShortField("checksum", 0),]

MPTCP_DSS_Ack64MapCsum = MPTCP_DSS_Ack64Map_AckMap64Csum
MPTCP_DSS_AckMap64Csum = MPTCP_DSS_Ack64Map_AckMap64Csum

class MPTCP_DSS_Ack64Map64(MPOption):
    """The longer DSS variant. It contains a 64bits mapping and a 64bits 
    ack seq"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 26<<4+2
    fields_desc = [ ByteField("length", 26),
                    _DSS_HDR,
                    FlagsField("flags", "mMaA", 5, "AaMmF"),
                    LongField("data_ack", 0),
                    LongField("dsn", 0),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),]

class MPTCP_DSS_Ack64Map64Csum(MPOption):
    """The longer DSS variant. It contains a 64bits mapping and a 64bits 
    ack seq"""
    name = "Multipath TCP Data Sequence Signal"
    subtype = 2
    subsubtype = 28<<4+2
    fields_desc = [ ByteField("length", 28),
                    _DSS_HDR,
                    FlagsField("flags", "mMaA", 5, "AaMmF"),#"AaMmF"),
                    LongField("data_ack", 0),
                    LongField("dsn", 0),
                    IntField("subflow_seqnum", 0),
                    ShortField("datalevel_len", 0),
                    XShortField("checksum", 0),]

MPTCP_DSS = MPTCP_DSS_Ack64Map64Csum # alias for most generic DSS


class MPTCP_AddAddr(MPOption):
    name = "Multipath TCP Add Address"
    subtype = 3
    subsubtype = 8<<4+3
    fields_desc = [ ByteField("length", 8),
                    BitEnumField("subtype", 3, 4, MPTCP_subtypes),
                    BitField("ipver", 4, 4),
                    ByteField("address_id", 0),
                    IPField("adv_addr", "0.0.0.0"),] #conditional length

class MPTCP_AddAddrPort(MPOption):
    name = "Multipath TCP Add Address"
    subtype = 3
    subsubtype = 10<<4+3
    fields_desc = [ ByteField("length", 10),
                    BitEnumField("subtype", 3, 4, MPTCP_subtypes),
                    BitField("ipver", 4, 4),
                    ByteField("address_id", 0),
                    IPField("adv_addr", "0.0.0.0"),
                    ShortField("port",0),] #conditional length
##FIXME: support IPv6
#if conf.ipv6_enabled:
#class MPTCP_AddAddr6(MPOption):
#    name = "Multipath TCP Add Address"
#    subtype = 3
#    subsubtype = 20<<4+3
#    fields_desc = [ ByteField("length", 20),
#                    BitEnumField("subtype", 3, 4, MPTCP_subtypes),
#                    BitField("ipver", 6, 4),
#                    ByteField("address_id", 0),
#                    IP6Field("adv_addr", "::1"),
#                    ShortField("port",0),]

class MPTCP_RemoveAddr(MPOption):
    name = "Multipath TCP Remove Address"
    subtype = 4
    subsubtype = 4<<4+4
    fields_desc = [ FieldLenField("length", 4, count_of="addr_ids", fmt="B",
                        adjust=lambda p,l: l+3), 
                    BitEnumField("subtype", 4, 4, MPTCP_subtypes),
                    BitField("reserved", 0, 4),
                    FieldListField("addr_ids", [0], ByteField("",0), 
                        count_from = lambda pkt: pkt.length-3) ]
                    
                    
class MPTCP_Prio(MPOption):
    name = "Multipath TCP priority"
    subtype = 5
    subsubtype = 3<<4+5
    fields_desc = [ ByteField("length", 3),
                    BitEnumField("subtype", 5, 4, MPTCP_subtypes),
                    BitField("reserved_flags", 0, 3),
                    BitField("backup_flow", 0, 1),]
class MPTCP_Prio_AddrID(MPOption):
    name = "Multipath TCP priority"
    subtype = 5
    subsubtype = 4<<4+5
    fields_desc = [ ByteField("length", 4),
                    BitEnumField("subtype", 5, 4, MPTCP_subtypes),
                    BitField("reserved_flags", 0, 3),
                    BitField("backup_flow", 0, 1),
                    ByteField("addr_id",0),]

class MPTCP_Fail(MPOption):
    name = "Multipath TCP Fallback"
    subtype = 6
    subsubtype = 12<<4+6
    fields_desc = [ ByteField("length", 12),
                    BitEnumField("subtype", 6, 4, MPTCP_subtypes),
                    BitField("reserved", 0, 12),
                    LongField("seq",0)]

class MPTCP_Fastclose(MPOption):
    name = "Multipath TCP Fastclose"
    subtype = 7
    subsubtype = 12<<4+7
    fields_desc = [ ByteField("length", 12),
                    BitEnumField("subtype", 6, 4, MPTCP_subtypes),
                    BitField("reserved", 0, 12),
                    LongField("rcv_key",0)]

# vim: set ts=4 sts=4 sw=4 et:
