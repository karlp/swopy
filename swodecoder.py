#!/usr/bin/env
from __future__ import print_function
import argparse
import time
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
    _bc = 0


    in_sync = False
    while True:
        frame = []
        while not in_sync:
            b = (yield)
            _bc += 1
            if b == 0:
                frame.append(b)
            else:
                if b == 0x80 and (len(frame) >= 5):
                    frame.append(b)
                else:
                    print("Not in sync: invalid byte for sync frame: offset=%d (%#x) %d (%#x)" % (_bc, _bc, b, b))
                    frame = []

            print("Frame so far", frame)
            # Allow longer runs of zeros, as long as they end up as a sync
            if frame[-6:] == synchro:
                in_sync = True
                target.send(SynchroPacket())

        # Ok, we're in sync now, need to be prepared for anything at all...
        b = yield
        _bc += 1
        if b == 0:
            fin = False
            frame = []
            while not fin:
                if (b == 0):
                    frame.append(b)
                else:
                    if b == 0x80 and (len(frame) == 5):
                        frame.append(b)
                    else:
                        #print("invalid sync frame byte? trying to resync: %d" % b)
                        print("invalid sync frame byte? pretending it didn't happen offset: %d(%#x) %d (%#x), frame was %s" % (_bc, _bc, b, b, frame))
                        fin = True
                if frame == synchro:
                    target.send(SynchroPacket())
                    fin = True
                else:
                    b = yield
                    _bc += 1
                print("Frame2 so far", frame)

        elif ((b & 0x3) == 0):
            if b == 0x70:
                print("Overflow!")
                target.send(OverflowPacket())
            else:
                print("Protocol packet decoding not handled, breaking stream to next sync offset=%d (%#x) :( byte was: %d (%x)" % (_bc, _bc, b, b))
                in_sync = False
        else:
            address = (b & 0xf8) >> 3
            source = (b & 0x4) >> 2
            plen = b & 0x3
            rlen = zip([0, 1,2,3], [0, 1,2,4])[plen][1] # 1,2,4 byte mappings
            data = []
            for x in range(rlen):
                b = yield
                _bc += 1
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
            print(f)
            continue
        if f.address == valid_address or valid_address == -1:
            print(f)
            """
            if (f.size == 1):
                print(chr(f.data), end='')
            else:
                print("Channel %d: %d byte value: %d : %#x" % (f.address, f.size, f.data, f.data))
            """



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
    ap.add_argument("--follow", "-f", action="store_true", help="Seek to the 1024 bytes before the end of file first!", default=False)
    opts = ap.parse_args()

    parser = PacketParser(target=PacketReceiverConsolePrinter(opts.address))

    with opts.file:
        print("file pos = ", opts.file.tell())
        if opts.follow:
            print("Seeking to end of file!")
            opts.file.seek(-1024, 2)
        bb = opts.file.read(1024)

        while True:
            print("file pos = ", opts.file.tell())
            if len(bb):
                [parser.send(ord(b)) for b in bb]
            else:
                if opts.follow:
                    time.sleep(0.5)
                else:
                    print("# All finished!")
                    break

            bb = opts.file.read(1024)
