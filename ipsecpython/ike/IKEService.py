import logging
import asyncio
import os

from enum import IntEnum
from functools import reduce
import operator
import os
import struct
from hashlib import sha256
from struct import unpack
import binascii
import struct

from . import payloads
# from ike.util import pubkey
# from ike.util.external import run_setkey
# from .util.cipher import Camellia
# from . import const
# from . import proposal
from ..DiffieHellman import DiffieHellman
from .prf import prf, prfplus

logger = logging.getLogger('MAIN')
logger.setLevel(logging.DEBUG)

IKE_HEADER = struct.Struct('!2Q4B2L')

IKE_HDR_FLAGS = dict(
    R=0b00100000,
    I=0b00001000
)

IKE_VERSION = (2 << 4 | 0)

import binascii

def dump(src):
    """
    Returns data in hex format in groups of 4 octets delimited by spaces for debugging purposes.
    """
    return b' '.join(binascii.hexlify(bytes(x)) for x in zip(src[::4], src[1::4], src[2::4], src[3::4]))

import math

def to_bytes(x):
    l = math.ceil(x.bit_length() / 8)
    return x.to_bytes(l, 'big')

class State(IntEnum):
    SEND_INIT_REQUEST = 0
    WAIT_INIT_REQUEST = 1
    SEND_INIT_RESPONSE = 2
    WAIT_INIT_RESPONSE = 3
    SEND_AUTH_REQUEST = 4
    WAIT_AUTH_REQUEST = 5
    SEND_AUTH_RESPONSE = 6
    WAIT_AUTH_RESPONSE = 7
    SEND_CHILD_SA_REQUEST = 8
    WAIT_CHILD_SA_REQUEST = 9
    SEND_CHILD_SA_RESPONSE = 10
    WAIT_CHILD_SA_RESPONSE = 11
    START_IPSEC_SA_PROTECTION = 12


class ExchangeType(IntEnum):
    IKE_SA_INIT = 34
    IKE_AUTH = 35
    CREATE_CHILD_SA = 36
    INFORMATIONAL = 37


class IkeError(Exception):
    pass


class IKE(object):
    iSPI: int
    rSPI: int
    diffie_hellman: DiffieHellman

    def __init__(self, address, peer, dh_group=14, nonce_len=32):
        """

        :param address: local address tuple(host, port)
        :param peer: remote address tuple(host, port)
        :param dh_group: diffie hellman group number
        :param nonce_len: length of Nonce data
        """
        self.iSPI = 0
        self.rSPI = 0
        self.diffie_hellman = DiffieHellman(dh_group)
        self.Ni = os.urandom(nonce_len)
        self.packets = list()
        self.state = State.SEND_INIT_REQUEST
        self.address = address
        self.peer = peer

    def init_send(self):
        """
        Generates the first (IKE_INIT) packet for Initiator

        :return: bytes() containing a valid IKE_INIT packet
        """
        packet = Packet()
        packet.add_payload(payloads.SA())
        packet.add_payload(payloads.KE(diffie_hellman=self.diffie_hellman))
        packet.add_payload(payloads.Nonce(nonce=self.Ni))
        packet.iSPI = self.iSPI = packet.payloads[0].spi
        logger.debug("\n\niSPI: {}\n\n".format(str(self.iSPI)))
        self.state = State.WAIT_INIT_RESPONSE
        return bytes(packet)

    # def auth_send(self):
    #     """
    #     Generates the second (IKE_AUTH) packet for Initiator

    #     :return: bytes() containing a valid IKE_INIT packet
    #     """
    #     assert len(self.packets) == 2
    #     packet = Packet(exchange_type=const.ExchangeType.IKE_AUTH, iSPI=self.iSPI, rSPI=self.rSPI)

    #     # Add IDi (35)
    #     id_payload = payloads.IDi()
    #     packet.add_payload(id_payload)

    #     # Add AUTH (39)
    #     signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
    #     packet.add_payload(payloads.AUTH(signed_octets))

    #     # Add SA (33)
    #     self.esp_SPIout = int.from_bytes(os.urandom(4), 'big')
    #     packet.add_payload(payloads.SA(proposals=[
    #         proposal.Proposal(protocol=const.ProtocolID.ESP, spi=self.esp_SPIout, last=True, transforms=[
    #             ('ENCR_CAMELLIA_CBC', 256), ('ESN',), ('AUTH_HMAC_SHA2_256_128',)
    #         ])
    #     ]))

    #     # Add TSi (44)
    #     packet.add_payload(payloads.TSi(addr=self.address))

    #     # Add TSr (45)
    #     packet.add_payload(payloads.TSr(addr=self.peer))

    #     # Add N(INITIAL_CONTACT)
    #     packet.add_payload(payloads.Notify(notify_type=const.MessageType.INITIAL_CONTACT))

    #     self.packets.append(packet)
    #     self.state = State.AUTH

    #     return self.encrypt_and_hmac(packet)

    def init_recv(self, packet):
        """
        Parses the IKE_INIT response packet received from Responder.

        Assigns the correct values of rSPI and Nr
        Calculates Diffie-Hellman exchange and assigns all keys to self.

        """
        self.iSPI = packet.iSPI
        logger.debug("\n\niSPI: {}\n\n".format(str(self.iSPI)))

        for p in packet.payloads:
            if p._type == payloads.Type.Nr:
                self.Nr = p._data
                logger.debug(u"Responder nonce {}".format(binascii.hexlify(self.Nr)))
            elif p._type == payloads.Type.KE:
                int_from_bytes = int.from_bytes(p.kex_data, 'big')
                self.diffie_hellman.derivate(int_from_bytes)
            else:
                logger.debug('Ignoring: {}'.format(p))

        logger.debug('Nonce I: {}\nNonce R: {}'.format(binascii.hexlify(self.Ni), binascii.hexlify(self.Nr)))
        logger.debug('DH shared secret: {}'.format(binascii.hexlify(self.diffie_hellman.__shared_secret)))

        SKEYSEED = prf(self.Ni + self.Nr, self.diffie_hellman.__shared_secret)

        logger.debug(u"SKEYSEED is: {0!r:s}\n".format(binascii.hexlify(SKEYSEED)))

        keymat = prfplus(SKEYSEED, (self.Ni + self.Nr +
                                    to_bytes(self.iSPI) + to_bytes(self.rSPI)),
                         32 * 7)
        #3 * 32 + 2 * 32 + 2 * 32)

        logger.debug("Got %d bytes of key material" % len(keymat))
        # get keys from material
        ( self.SK_d,
          self.SK_ai,
          self.SK_ar,
          self.SK_ei,
          self.SK_er,
          self.SK_pi,
          self.SK_pr ) = unpack("32s" * 7, keymat)  # XXX: Should support other than 256-bit algorithms, really.

        logger.debug("SK_ai: {}".format(dump(self.SK_ai)))
        logger.debug("SK_ei: {}".format(dump(self.SK_ei)))

    # def authenticate_peer(self, auth_data, peer_id, message):
    #     """
    #     Verifies the peers authentication.
    #     """
    #     logger.debug('message: {}'.format(dump(message)))
    #     signed_octets = message + self.Ni + prf(self.SK_pr, peer_id._data)
    #     auth_type = const.AuthenticationType(struct.unpack(const.AUTH_HEADER, auth_data[:4])[0])
    #     assert auth_type == const.AuthenticationType.RSA
    #     logger.debug(dump(auth_data))
    #     try:
    #         return pubkey.verify(signed_octets, auth_data[4:], os.path.dirname(os.path.abspath(__file__)) + '/../../config/peer.pem')
    #     except pubkey.VerifyError:
    #         raise IkeError("Remote peer authentication failed.")

    # def auth_recv(self):
    #     """
    #     Handle peer's IKE_AUTH response.
    #     """
    #     id_r = auth_data = None
    #     for p in self.packets[-1].payloads:
    #         if p._type == payloads.Type.IDr:
    #             id_r = p
    #             logger.debug('Got responder ID: {}'.format(dump(bytes(p))))
    #         if p._type == payloads.Type.AUTH:
    #             auth_data = p._data
    #         if p._type == payloads.Type.SA:
    #             logger.debug('ESP_SPIin: {}'.format(p.spi))
    #             self.esp_SPIin = p.spi
    #             for proposal in p.proposals:
    #                 logger.debug("Proposal: {}".format(proposal.__dict__))
    #                 logger.debug(proposal.spi)
    #     if id_r is None or auth_data is None:
    #         raise IkeError('IDr missing from IKE_AUTH response')
    #     message2 = bytes(self.packets[1])
    #     authenticated = self.authenticate_peer(auth_data, id_r, message2)
    #     assert authenticated
    #     keymat = prfplus(self.SK_d, self.Ni + self.Nr, 4 * 32)
    #     (self.esp_ei,
    #       self.esp_ai,
    #       self.esp_er,
    #       self.esp_ar,
    #      ) = unpack("32s" * 4, keymat)

    # def decrypt(self, data):
    #     """
    #     Decrypts an encrypted (SK, 46) IKE payload using self.SK_er

    #     :param data: Encrypted IKE payload including headers (payloads.SK())
    #     :return: next_payload, data_containing_payloads
    #     :raise IkeError: If packet is corrupted.
    #     """
    #     next_payload, is_critical, payload_len = const.PAYLOAD_HEADER.unpack(data[:const.PAYLOAD_HEADER.size])
    #     next_payload = payloads.Type(next_payload)
    #     logger.debug("next payload: {!r}".format(next_payload))
    #     try:
    #         iv_len = 16
    #         iv = bytes(data[const.PAYLOAD_HEADER.size:const.PAYLOAD_HEADER.size + iv_len])
    #         ciphertext = bytes(data[const.PAYLOAD_HEADER.size + iv_len:payload_len])  # HMAC size
    #     except IndexError:
    #         raise IkeError('Unable to decrypt: Malformed packet')
    #     logger.debug('IV: {}'.format(dump(iv)))
    #     logger.debug('CIPHERTEXT: {}'.format(dump(ciphertext)))
    #     # Decrypt
    #     cipher = Camellia(self.SK_er, iv=iv)
    #     decrypted = cipher.decrypt(ciphertext)
    #     logger.debug("Decrypted packet from responder: {}".format(dump(decrypted)))
    #     return next_payload, decrypted

    def parse_packet(self, data):
        packet = Packet(data=data)
        packet.header = data[0:IKE_HEADER.size]
        (packet.iSPI, packet.rSPI, next_payload, packet.version, exchange_type, packet.flags,
         packet.message_id, packet.length) = IKE_HEADER.unpack(packet.header)
        packet.exchange_type = ExchangeType(exchange_type)
        data = data[IKE_HEADER.size:]
        while next_payload:
            logger.debug('Next payload: {0!r}'.format(next_payload))
            logger.debug('{0} bytes remaining'.format(len(data)))
            try:
                payload = payloads.get_by_type(next_payload)(data=data)
            except KeyError as e:
                logger.error("Unidentified payload {}".format(e))
                payload = payloads._IkePayload(data=data)
            packet.payloads.append(payload)
            logger.debug('Payloads: {0!r}'.format(packet.payloads))
            next_payload = payload.next_payload
            data = data[payload.length:]

        return packet

    # def parse_packet(self, data):
    #     """
    #     Parses a received packet in to Packet() with corresponding payloads.
    #     Will decrypt encrypted packets when needed.

    #     :param data: bytes() IKE packet from wire.
    #     :return: Packet() instance
    #     :raise IkeError: on malformed packet
    #     """
    #     packet = Packet(data=data)
    #     packet.header = data[0:const.IKE_HEADER.size]
    #     (packet.iSPI, packet.rSPI, next_payload, packet.version, exchange_type, packet.flags,
    #      packet.message_id, packet.length) = const.IKE_HEADER.unpack(packet.header)
    #     packet.exchange_type = const.ExchangeType(exchange_type)
    #     if packet.exchange_type == const.ExchangeType.IKE_SA_INIT:
    #         logger.debug("Packed parsed successfully")
    #         self.packets.append(packet)
    #         return packet
    #     elif self.iSPI != packet.iSPI:
    #         raise IkeError("Initiator SPI mismatch, packet to an unknown IKE SA")
    #     elif not self.rSPI:
    #         logger.debug("Setting responder SPI: {0:x}".format(packet.rSPI))
    #         self.rSPI = packet.rSPI
    #     elif self.rSPI != packet.rSPI:
    #         raise IkeError("Responder SPI mismatch, packet to an unknown IKE SA")
    #     if packet.message_id - int(self.state) != 1:
    #         logger.debug("message ID {} at state {!r}".format(packet.message_id, self.state))
    #     logger.debug("next payload: {!r}".format(next_payload))
    #     if next_payload == 46:
    #         self.verify_hmac(data)
    #         next_payload, data = self.decrypt(data[const.IKE_HEADER.size:])
    #     else:
    #         data = data[const.IKE_HEADER.size:]
    #     while next_payload:
    #         logger.debug('Next payload: {0!r}'.format(next_payload))
    #         logger.debug('{0} bytes remaining'.format(len(data)))
    #         try:
    #             payload = payloads.get_by_type(next_payload)(data=data)
    #         except KeyError as e:
    #             logger.error("Unidentified payload {}".format(e))
    #             payload = payloads._IkePayload(data=data)
    #         packet.payloads.append(payload)
    #         logger.debug('Payloads: {0!r}'.format(packet.payloads))
    #         next_payload = payload.next_payload
    #         data = data[payload.length:]
    #     logger.debug("Packed parsed successfully")
    #     self.packets.append(packet)
    #     return packet


class Packet(object):
    def __init__(self, data=None, exchange_type=None, message_id=0, iSPI=0, rSPI=0):
        self.raw_data = data
        if exchange_type is None:
            exchange_type=ExchangeType.IKE_SA_INIT
        self.payloads = list()
        self.iSPI = iSPI
        self.rSPI = rSPI
        self.message_id = message_id
        self.exchange_type = exchange_type

    def add_payload(self, payload):
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

class IKEService(asyncio.DatagramProtocol):
    def __init__(self, address, peer):
        self.ike = IKE(address, peer)

    def connection_made(self, transport):
        self.transport = transport
        sock = self.transport.get_extra_info("socket")
        address = sock.getsockname()
        peer = sock.getpeername()
        logger.debug("Socket created from {} to {}".format(address, peer))
        logger.info("Sending INIT")
        self.transport.sendto(self.ike.init_send())

    def datagram_received(self, data, address):
        (host, port) = address
        logger.info("Received %r from %s:%d" % (data, host, port))
        packet = self.ike.parse_packet(data=data)
        logger.info('{} message {}'.format(packet.exchange_type.name, packet.message_id))
        # TODO
        # if self.ike.state == State.WAIT_INIT_RESPONSE and 
        if self.ike.state == State.WAIT_INIT_RESPONSE:
            # Drop your request and accept incoming
            self.ike.state = State.WAIT_INIT_REQUEST

        if self.ike.state == State.WAIT_INIT_REQUEST and packet.exchange_type == ExchangeType.IKE_SA_INIT:
            self.ike.init_recv(packet)
            ike_auth = self.ike.auth_send()
            logger.info("Sending AUTH")
            self.transport.sendto(ike_auth)
            logger.info("IKE AUTH SENT")
        elif self.ike.state == State.WAIT_AUTH_REQUEST and packet.exchange_type == ExchangeType.IKE_AUTH:
            self.ike.auth_recv()

    def connectionRefused(self):
        logger.info("No one listening")