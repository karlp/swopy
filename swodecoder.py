#!/usr/bin/env
from __future__ import print_function
import argparse
import io
import sys
import struct

class ITMDWTPacket():
    pass

class SynchroPacket(ITMDWTPacket):
    def __repr__(self):
        return "SynchroPacket"

class OverflowPacket(ITMDWTPacket):
    def __repr__(self):
        return "OverflowPacket"

class SourcePacket(ITMDWTPacket):
    def __init__(self, address, source, size, data):
        self.address = address
        self.source = source
        self.size = size
        if size == 1:
            self.data = data[0]
        elif size == 2:
            self.data = struct.unpack_from("<H", bytearray(data))[0]
        elif size == 4:
            self.data = struct.unpack_from("<I", bytearray(data))[0]

    def __repr__(self):
        if self.size == 1:
            return "SourcePacket8(A=%d, S=%d, D=%c)" % (self.address, self.source, chr(self.data))
        if self.size == 2:
            return "SourcePacket16(A=%d, S=%d, D=%d (%#x)" % (self.address, self.source, self.data, self.data)
        if self.size == 4:
            return "SourcePacket32(A=%d, S=%d, D=%d (%#x)" % (self.address, self.source, self.data, self.data)

def coroutine(func):
    def start(*args,**kwargs):
        cr = func(*args,**kwargs)
        cr.next()
        return cr
    return start

@coroutine
def PacketParser(target, skip_to_sync=True):
    """
    Process data arriving in chunks, and successively yield parsed ITM/DWT packets
    """
    synchro = [0,0,0,0,0,0x80]

    in_sync = False
    while True:
        frame = []
        while not in_sync:
            b = (yield)
            if b != 0:
                if (len(frame) == 5) and (b == 0x80):
                    frame.append(b)
                else:
                    print("not in sync, skipping non zero", b)
            else:
                frame.append(b)
            #print("Frame so far", frame)
            if frame == synchro:
                in_sync = True
                target.send(SynchroPacket())

        # Ok, we're in sync now, need to be prepared for anything at all...
        b = yield
        if b == 0:
            fin = False
            frame = []
            while not fin:
                if ((b == 0) or ((len(frame) == 5) and (b == 0x80))):
                    frame.append(b)
                if frame == synchro:
                    target.send(SynchroPacket())
                    fin = True
                b = yield

        elif ((b & 0x3) == 0):
            if b == 0x70:
                print("Overflow!")
                target.send(OverflowPacket())
            else:
                print("Protocol packet decoding not handled, breaking stream to next sync :(")
                in_sync = False
        else:
            address = (b & 0xf8) >> 3
            source = (b & 0x4) >> 2
            plen = b & 0x3
            rlen = zip([0, 1,2,3], [0, 1,2,4])[plen][1] # 1,2,4 byte mappings
            data = []
            for x in range(rlen):
                b = yield
                data.append(b)
            ss = SourcePacket(address, source, rlen, data)
            target.send(ss)





@coroutine
def InsaneVerbosePacketReceiver():
    """ A simple co-routine "sink" for receiving
        full frames.
    """
    while True:
        frame = (yield)
        print("Got frame: %s" % frame)

@coroutine
def PacketReceiverConsolePrinter(valid_address=-1):
    while True:
        f = yield
        if not hasattr(f, "address"):
            # Skip things like synchro packets
            continue
        if f.address == valid_address or valid_address == -1:
            try:
                print(chr(f.data), end='')
            except ValueError:
                print("?", end='')



def demodemo():
    data = """37 01 38 01 39 01 30 01  31 01 32 01 33 01 34 01
    35 00 00 00 00 00 80 01  36 01 37 01 38 01 39 01
    30 01 31 01 32 01 33 01  34 01 35 00 00 00 00 00
    80 01 36 01 37 01 38 01  39 01 30 01 31 01 32 01"""
    data = data.split()
    dd = [int(x, base=16) for x in data]

    def chunker(ll, n):
        for i in range(0, len(ll), n):
            yield ll[i:i+n]

    chunks = [chunk for chunk in chunker(dd, 10)]

    parser = PacketParser(target=InsaneVerbosePacketReceiver())

    for c in chunks:  ## aka, while we read a file....
        for b in c:
            parser.send(b)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('file', type=argparse.FileType('rb', 0), help="swo binary output file to parse", default="-")
    ap.add_argument("--address", "-a", type=int, default=-1, help="which channels to print, -1 for all")
    opts = ap.parse_args()

    parser = PacketParser(target=PacketReceiverConsolePrinter(opts.address))

    with opts.file:
        while True:
            parser.send(ord(opts.file.read(1)))
