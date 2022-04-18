import operator
from enum import IntEnum
from functools import reduce
import struct


IKE_VERSION = (2 << 4 | 0)  # Major << 4 | Minor

# iSPI, rSPI, NextPayload, (MjVer, MnVer), ExchangeType, Flags, MessageID, Len
IKE_HEADER = struct.Struct('!2Q4B2L')


class ExchangeType(IntEnum):
    IKE_SA_INIT = 34
    IKE_AUTH = 35
    CREATE_CHILD_SA = 36
    INFORMATIONAL = 37


IKE_HDR_FLAGS = dict(
    R=0b00100000,
    I=0b00001000
)


class IKEPacket(object):
    """
    An IKE packet.
    To generate packets:
    #. instantiate an Packet()
    #. add payloads by Packet.add_payload(<payloads.IkePayload instance>)
    #. send bytes(Packet) to other peer.
    Received packets should be generated by IKE.parse_packet().
    """

    def __init__(self, data=None, exchange_type=None, message_id=0, iSPI=0, rSPI=0):
        self.raw_data = data
        if exchange_type is None:
            exchange_type = ExchangeType.IKE_SA_INIT
        self.payloads = list()
        self.iSPI = iSPI
        self.rSPI = rSPI
        self.message_id = message_id
        self.exchange_type = exchange_type

    def add_payload(self, payload):
        """
        Adds a payload to packet, updating last payload's next_payload field
        """
        if self.payloads:
            self.payloads[-1].next_payload = payload._type
        self.payloads.append(payload)

    def __bytes__(self):
        if self.raw_data is not None:
            return self.raw_data
        data = reduce(operator.add, (bytes(x) for x in self.payloads))
        length = len(data) + IKE_HEADER.size
        header = bytearray(IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            self.payloads[0]._type,
            IKE_VERSION,
            self.exchange_type,
            IKE_HDR_FLAGS['I'],
            self.message_id,
            length
        ))
        return bytes(header + data)
