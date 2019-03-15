#!/usr/bin/env python3
from __future__ import print_function
import serial
import struct
from enum import IntEnum
import time

crc16_table = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040]


class SubmessageId(IntEnum):
    CREATE_CLIENT = 0
    CREATE = 1
    GET_INFO = 2
    DELETE = 3
    STATUS_AGENT = 4
    STATUS = 5
    INFO = 6
    WRITE_DATA = 7
    READ_DATA = 8
    DATA = 9
    ACKNACK = 10
    HEARTBEAT = 11
    RESET = 12
    FRAGMENT = 13


class ObjectKind(IntEnum):
    INVALID = 0x00
    PARTICIPANT = 0x01
    TOPIC = 0x02
    PUBLISHER = 0x03
    SUBSCRIBER = 0x04
    DATAWRITER = 0x05
    DATAREADER = 0x06
    TYPE = 0x0A
    QOSPROFILE = 0x0B
    APPLICATION = 0x0C
    AGENT = 0x0D
    CLIENT = 0x0E


def string_to_hex(string):
    return ":".join("{:02x}".format(ord(c)) for c in string)

def header(sessionId, streamId, sequenceNr, clientKey=None):
    if 0 <= sessionId <= 0x7f:
        hdr = struct.pack("<BBHI", sessionId, streamId, sequenceNr, clientKey)
    elif 0x80 <= sessionId <= 0xFF:
        hdr = struct.pack("<BBH", sessionId, streamId, sequenceNr)
    # print("hdr:", string_to_hex(hdr))
    return bytearray(hdr)


def submessage(submessageId, flags, payload):
    subm = bytearray()
    submessageLength = len(payload)
    print("subm l", submessageLength)
    subhdr = struct.pack("<BBH", submessageId, flags, submessageLength)
    subm += subhdr
    subm += payload
    return subm


def bytes_to_hex_str(b):
    hex_str = ':'.join('%02x' % i for i in b)
    return '\n'.join(hex_str[12 * i: 12 * i + 12] for i in range(0, int(len(hex_str)/12)+1))


SESSION_ID_NONE_WITH_CLIENT_KEY = 0x00
SESSION_ID_NONE_WITHOUT_CLIENT_KEY = 0x80

STREAMID_NONE = 0x00
STREAMID_BUILTIN_BEST_EFFORTS = 0x01
STREAMID_BUILTIN_RELIABLE = 0x80

# from serial protocol
UXR_FRAMING_BEGIN_FLAG = 0x7e
UXR_FRAMING_ESC_FLAG = 0x7D
UXR_FRAMING_XOR_FLAG = 0x20


class Client:
    def __init__(self, port):
        self.serial = serial.Serial(port, 115200)

    def add_next_octet(self, buf, octet):
        if octet in [UXR_FRAMING_BEGIN_FLAG, UXR_FRAMING_ESC_FLAG]:
            buf.append(UXR_FRAMING_ESC_FLAG)
            buf.append(octet^UXR_FRAMING_XOR_FLAG)
        else:
            buf.append(octet)

    def create_client(self):
        # XRCE header
        xrce_msg = bytearray()
        hdr = header(sessionId=SESSION_ID_NONE_WITHOUT_CLIENT_KEY, streamId=STREAMID_NONE, sequenceNr=0)
        xrce_msg += hdr
        pl = bytearray()
        request_id = int("00AA", 16) # AA:00
        objectid_prefix = 0xFF # object_id = {0xFF, 0xFE}
        pl += struct.pack("<HBB", request_id, objectid_prefix, objectid_prefix&0xF0 + int(ObjectKind.CLIENT))
        pl += struct.pack("<cccc", b'X', b'R', b'C', b'E')
        pl += struct.pack("<BB", 0x01, 0x00)   # version
        pl += struct.pack("<BB", 0x0F, 0x0F)   # vendor

        tnow = time.time()
        pl += struct.pack("<l", int(tnow))
        # pl += struct.pack("<L", int(tnow-int(tnow)*1e9))
        pl += struct.pack("<l", 0)

        # pl += struct.pack("<l", 1518905996)
        # pl += struct.pack("<l", 500000000)

        pl += struct.pack("<L", int("55443322", 16)) # client_key: 0x22, 0x33, 0x44, 0x55
        pl += struct.pack("<B", 0xDD) # session id
        pl += struct.pack("<B", 0x00) # no properties

        subm = submessage(submessageId=SubmessageId.CREATE_CLIENT, flags=0x07, payload=pl)
        xrce_msg += subm

        msg_len = len(xrce_msg)

        print("xrce_msg:", msg_len)
        print("xrce_msg:\n"+str(bytes_to_hex_str(xrce_msg)))

        # serial transport header
        # # https://issues.omg.org/issues/spec/DDS-XRCE/1.0b1#issue-44481
        shdr = bytearray()
        shdr.append(0x01) # local addr
        shdr.append(0x00) # remote addr
        shdr += struct.pack("B", msg_len & 0xFF)
        shdr += struct.pack("B", msg_len >> 8)

        print("hdr:\n" + str(bytes_to_hex_str(shdr)))

        # framing
        shdr_stuf = bytearray()
        shdr_stuf.append(UXR_FRAMING_BEGIN_FLAG)
        for b in shdr:
            self.add_next_octet(shdr_stuf, b)
        xrce_stuf = bytearray()
        for b in xrce_msg:
            self.add_next_octet(xrce_stuf, b)

        # CRC POLY 0x8005
        crc = 0
        for b in xrce_msg:
            crc = (crc >> 8) ^ crc16_table[(crc^b)&0xFF]
        print("crc", hex(crc & 0xFF), hex(crc >> 8))

        # footer
        sftr = bytearray()
        sftr += struct.pack("B", crc & 0xFF)
        sftr += struct.pack("B", crc >> 8)

        print("ftr:\n" + str(bytes_to_hex_str(sftr)))

        msg = bytearray()
        msg += shdr_stuf
        msg += xrce_stuf
        msg += sftr

        # print("msg:\n" + str(bytes_to_hex_str(msg)))

        self.serial.write(msg)

        # print(int(self.serial.read(1)))

    def create_client_replay(self):
        #  7e 01 00 22 00 80 00 00 00 00 01 1a 00 00 01 ff
        #  fe 58 52 43 45 01 00 01 0f 0f 06 00 00 76 49 2a
        #  1a 2b fa e2 c9 81 00 19 bd
        msg = bytearray([0x7e, 0x01, 0x00, 0x22, 0x00, 0x80, 0x00, 0x00,
                         0x00, 0x00, 0x01, 0x1a, 0x00, 0x00, 0x01, 0xff,
                         0xfe, 0x58, 0x52, 0x43, 0x45, 0x01, 0x00, 0x01,
                         0x0f, 0x0f, 0x06, 0x00, 0x00, 0x76, 0x49, 0x2a,
                         0x1a, 0x2b, 0xfa, 0xe2, 0xc9, 0x81, 0x00, 0x19, 0xbd])

        msg2 = bytearray([0x80, 0x00, 0x00,
                         0x00, 0x00, 0x01, 0x1a, 0x00, 0x00, 0x01, 0xff,
                         0xfe, 0x58, 0x52, 0x43, 0x45, 0x01, 0x00, 0x01,
                         0x0f, 0x0f, 0x06, 0x00, 0x00, 0x76, 0x49, 0x2a,
                         0x1a, 0x2b, 0xfa, 0xe2, 0xc9, 0x81, 0x00])

        crc = 0
        for b in msg2:
            crc = (crc >> 8) ^ crc16_table[(crc^b)&0xFF]
        # *crc = (*crc >> 8) ^ crc16_table[(*crc ^ data) & 0xFF];
        print("crc", hex(crc & 0xFF), hex(crc >> 8))

        self.serial.write(msg)


if __name__ == '__main__':
    cl = Client("/home/christian/pts2")
    cl.create_client()
    # cl.create_client_replay()
