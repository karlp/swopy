#!/usr/bin/env python
__author__ = 'karlp'
"""
Decode bytestreams from wireshark into what the command is...
"""
import struct
import sys
import binascii

import magic

def decode_dbg_cmd(xx):
    print("xx = ", xx)
    subcmd, = struct.unpack("<B", xx[0])
    if subcmd == magic.STLINK_DEBUG_APIV2_WRITEDEBUGREG:
        reg, value = struct.unpack("<II", xx[1:9])
        return "WRITE_DEBUG_REG[reg=%#x, value=%d(%#x)]" % (reg, value, value)
    elif subcmd == magic.STLINK_DEBUG_APIV2_READDEBUGREG:
        reg, = struct.unpack("<I", xx[1:5])
        return "READ_DEBUG_REG[reg=%#x]" % (reg)
    elif subcmd == magic.STLINK_DEBUG_APIV2_WRITEREG:
        reg, value = struct.unpack("<II", xx[1:9])
        return "WRITE_REG[reg=%#x, value=%d(%#x)]" % (reg, value, value)
    elif subcmd == magic.STLINK_DEBUG_READMEM32:
        reg, length = struct.unpack("<IH", xx[1:7])
        return "READMEM32[addr=%#x, len=%d(%#x)]" % (reg, length, length)
    elif subcmd == magic.STLINK_DEBUG_WRITEMEM32:
        reg, length = struct.unpack("<IH", xx[1:7])
        return "WRITEMEM32[addr=%#x, len=%d(%#x)]" % (reg, length, length)
    elif subcmd == magic.STLINK_DEBUG_APIV2_STOP_TRACE_RX:
        return "TRACE_STOP()"
    elif subcmd == magic.STLINK_DEBUG_APIV2_START_TRACE_RX:
        size, hz = struct.unpack("<HI", xx[1:7])
        return "TRACE_START[size=%d(%#x), hz=%d]" % (size, size, hz)


def decode(hexstring):
    #f235042004e007010000000000000000
    # 0000   f2 35 04 20 04 e0 07 01 00 00 00 00 00 00 00 00
    x = binascii.unhexlify(hexstring)
    cmd, = struct.unpack("<B", x[0])
    if cmd == magic.STLINK_DEBUG_COMMAND:
        return decode_dbg_cmd(x[1:])
    elif cmd == magic.STLINK_GET_TARGET_VOLTAGE:
        return "STLINK_GET_TARGET_VOLTAGE"
    else:
        raise ValueError("Unknown/unsupported command")


if __name__ == "__main__":
    print(decode(sys.argv[1]))
    #print(decode("f235042004e007010000000000000000"))



