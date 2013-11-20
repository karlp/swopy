__author__ = 'karlp'

import time
import logging
import struct
import sys
import cmd
import usb.core
import usb.util
from magic import *

logging.basicConfig(level=logging.DEBUG)

lame_py = None
def _lame_py_buffer_required(inp):
    return buffer(inp)

def _lame_py_buffer_not_required(inp):
    return inp

try:
    blob = [1,2,3,4]
    struct.unpack_from("<I", bytearray(blob))
    lame_py = _lame_py_buffer_not_required
    print("don't need lame pyt fix")
except TypeError:
    lame_py = _lame_py_buffer_required
    print(":( lame py required :(")


def find_stlink():
    dev = usb.core.find(idVendor=0x0483, idProduct=0x3748)
    #dev = usb.core.find(idProduct="STLINK/V2")

    if dev is None:
        raise ValueError('Device not found')

    dev.set_configuration()
    cfg = dev.get_active_configuration()
    interface_number = cfg[(0,0)].bInterfaceNumber
    alternate_setting = usb.control.get_interface(dev, interface_number)
    intf = usb.util.find_descriptor(
        cfg, bInterfaceNumber = interface_number,
        bAlternateSetting = alternate_setting
    )
    return dev


# 0x81 is regualr in, 0x2 is regular out, 0x83 is swo in
# Trace disable
#        stlink_usb_init_buffer(handle, STLINK_RX_EP, 2);
##        h->cmdbuf[h->cmdidx++] = STLINK_DEBUG_COMMAND;
#        h->cmdbuf[h->cmdidx++] = STLINK_DEBUG_APIV2_STOP_TRACE_RX;
#        res = stlink_usb_xfer(handle, h->databuf, 2);

class STLinkVersion():
    def __init__(self, blob):
        # blob = [36, 0, 131, 4, 72, 55]
        # Info : STLINK v2 JTAG v16 API v2 SWIM v0 VID 0x0483 PID 0x3748
        # woo, different byte ordering!
        ver = struct.unpack_from(">H", lame_py(blob[:2]))[0]
        self.vid, self.pid = struct.unpack_from("<HH", lame_py(blob[2:]))

        self.major_ver = (ver >> 12) & 0x0f
        self.jtag_ver = (ver >> 6) & 0x3f
        self.swim_ver = ver & 0x3f
        self.api_ver = 1
        if self.jtag_ver > 11:
            self.api_ver = 2

    def __repr__(self):
        return "STLINK v%d JTAG v%d API v%d SWIM v%d, VID %#x PID %#x" % (
            self.major_ver,
            self.jtag_ver,
            self.api_ver,
            self.swim_ver,
            self.vid,
            self.pid
        )

def stlink_pad(cmd):
    # Both actually seem to work....
    #return cmd
    return stlink_pad_real(cmd)

def stlink_pad_real(cmd):
    """
    make a zero buffer and fill the command in on top of it.  not very pretty :(
    """
    msg = [0 for x in range(STLINK_CMD_SIZE_V2)]
    for i,x in enumerate(cmd):
        msg[i] = x
    return msg

def xfer_normal_input(dev, cmd, expected_response_size, verbose=False):
    msg = stlink_pad(cmd)
    if verbose:
        print("Sending msg: ", msg)
    count = dev.write(STLINK_EP_TX, msg, 0)
    assert count == len(msg), "Failed to write cmd to usb"
    if expected_response_size:
        res = dev.read(STLINK_EP_RX, expected_response_size, 0)
        if verbose:
            print("Received: ", res)
        return res

def xfer_send_only_raw(dev, data):
    count = dev.write(STLINK_EP_TX, data, 0)
    assert count == len(data), "Failed to write data to usb"

def xfer_write_debug(dev, reg_addr, val):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_WRITEDEBUGREG]
    args = [ord(q) for q in struct.pack("<II", reg_addr, val)]
    cmd.extend(args)
    res = xfer_normal_input(dev, cmd, 2)
    logging.debug("WRITE DEBUG %#x ==> %d (%#08x)", reg_addr, val, val)
    #assert res ==

def xfer_read_debug(dev, reg_addr):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_READDEBUGREG]
    args = [ord(q) for q in struct.pack("<I", reg_addr)]
    cmd.extend(args)
    res = xfer_normal_input(dev, cmd, 8)
    status, unknown, val = struct.unpack_from("<HHI", lame_py(bytearray(res)))
    logging.debug("READ DEBUG: %#x ==> %d (%#08x)", reg_addr, val, val)
    assert status == 0x80, "failed to read debug reg?!"
    return val


def xfer_read32(dev, reg_addr, count):
    """
    count is in bytes!
    """
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_READMEM32]
    args = [ord(q) for q in struct.pack("<IH", reg_addr, count)]
    cmd.extend(args)
    res = xfer_normal_input(dev, cmd, count)
    u32s = struct.unpack("<%dI" % (count/4), res)
    logging.debug("READMEM32 %#x/%d returned: %s", reg_addr, count, [hex(i) for i in u32s])
    return u32s

def xfer_write32(dev, reg_addr, data):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_WRITEMEM32]
    dlen = len(data) * 4
    args = [ord(q) for q in struct.pack("<IH", reg_addr, dlen)]
    cmd.extend(args)
    xfer_normal_input(dev, cmd, 0)
    out_data = struct.pack("<%dI" % len(data), *data)
    xfer_send_only_raw(dev, out_data)
    logging.debug("WRITEMEM32 %#x/%d ==> %s", reg_addr, dlen, [hex(i) for i in data])

unknown_noop = True
def xfer_unknown_sync(dev):
    if unknown_noop:
        return
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_UNKNOWN_MAYBE_SYNC]
    res = xfer_normal_input(dev, cmd, 12)
    print("magic unknownn sync returned: ", res)
    return res

def get_version(dev):
    res = xfer_normal_input(dev, [STLINK_GET_VERSION, 0x80], 6)
    v = STLinkVersion(res)
    return v

def get_voltage(dev):
    res = xfer_normal_input(dev, [STLINK_GET_TARGET_VOLTAGE], 8)
    adc0, adc1 = struct.unpack_from("<II", lame_py(res))
    print(adc0, adc1)
    assert adc0 != 0
    return 2 * adc1 * (1.2 / adc0)

def get_mode(dev):
    res = xfer_normal_input(dev, [STLINK_GET_CURRENT_MODE], 2)[0]
    logging.debug("Get mode returned: %d", res)
    dev._swopy_mode = res
    return res

def leave_state(dev):
    cmd = None
    current = -1
    if hasattr(dev, "_swopy_mode"):
        current = dev._swopy_mode
    logging.debug("CUrrent saved mode is %d" %  current)
    if current == STLINK_MODE_DFU:
        logging.debug("Leaving dfu mode")
        cmd = [STLINK_DFU_COMMAND, STLINK_DFU_EXIT]
        dev._swopy_mode = 1 # "exit dfu" moves from mode 0 -> mode 1
    elif current == STLINK_MODE_DEBUG:
        logging.debug("Leaving debug mode")
        cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_EXIT]
        dev._swopy_mode = 1 # exit debug goes from mode 2 -> mode 1

    if cmd:
        xfer_normal_input(dev, cmd, 0)
    else:
        logging.debug("Ignoring mode we don't know how to leave/or need to leave")

def enter_state_debug(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_ENTER, STLINK_DEBUG_ENTER_SWD]
    res = xfer_normal_input(dev, cmd, 2)
    logging.debug("enter debug state returned: %s", res)
    # res[0] should be 0x80
    assert res[0] == 0x80, "enter state failed :("
    dev._swopy_mode = 2

def reset(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_RESETSYS]
    res = xfer_normal_input(dev, cmd, 2)
    logging.debug("reset returned: %s", res)

def run(dev):
    # This doesn't start it running :(
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_RUNCORE]
    res = xfer_normal_input(dev, cmd, 2)
    logging.debug("Run returned %s", res)
    return res

def status(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_STATUS]
    res = xfer_normal_input(dev, cmd, 2)
    print("status returned", res)
    # THis is NOT correct.  it shows "RUNNING" when the core is halted :(
    if res[0] == 0x80:
        return "RUNNING"
    elif res[0] == 0x81:
        return "HALTED"
    else:
        return "UNKNOWN"

def run2(dev):
    #stlink_usb_write_debug_reg(handle, DCB_DHCSR, DBGKEY|C_DEBUGEN);
    #  f2 35 f0 ed 00 e0 01 00 5f a0 00 00 00 00 00 00
    # pressing "run" in the target state pane in stlink sends this
    xfer_write_debug(dev, DCB_DHCSR, DCB_DHCSR_DBGKEY|DCB_DHCSR_C_DEBUGEN)
    # then just does a read of DCB_DHCSR,
    # then a read of 0x20000000 @ 4
    # then a read of x40023c1c @ 4 => 0x007800aa (FLASH_OBR, reeading option bytes and flash readout protection)
    # then one more read of DCB_DHCSR for good measure...

def trace_off(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_STOP_TRACE_RX]
    res = xfer_normal_input(dev, cmd, 2)
    logging.debug("STOP TRACE")

def trace_on(dev, buff=4096, hz=2000000):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_START_TRACE_RX]
    args = [ord(q) for q in struct.pack("<HI", buff, hz)]
    cmd.extend(args)
    # f240001080841e000000000000000000
    # This is what windows stlink sends:     f2 40 00 10 80 84 1e 00 00 00 00 00 00 00 00 00
    # 16 bit trace size = 0x1000
    # 32bit hz
    res = xfer_normal_input(dev, cmd, 2)
    logging.debug("START TRACE (buffer= %d, hz= %d)", buff, hz)

def enable_trace(dev, stim_bits=1, syncpackets=0):
    """
    setup and turn on trace for the given stimulus channels (default 0)
    sync packets are turned off by default.  You'll probably want them if
    you start doing lots of different channels and types
    """
    logging.info("Enabling trace")
    reg = xfer_read_debug(dev, DCB_DHCSR)
    # FIXME - if this isn't ok, probably need to reset it!

    # TODO - could be |= not hard write?
    xfer_write_debug(dev, DCB_DEMCR, DCB_DEMCR_TRCENA)

    reg = xfer_read32(dev, DBGMCU_CR, 4)[0]
    reg |= DBGMCU_CR_DEBUG_TRACE_IOEN | DBGMCU_CR_DEBUG_STOP | DBGMCU_CR_DEBUG_STANDBY | DBGMCU_CR_DEBUG_SLEEP
    xfer_write32(dev, DBGMCU_CR, [reg])

    # ST ref man says we set this to 1 even in async mode, it's still "one" pin wide
    xfer_write32(dev, TPIU_CSPSR, [1]) # currently selelct parallel size register ==> 1 bit wide.
    xfer_write32(dev, TPIU_ACPR, [0xb]) # async prescalar
    trace_off(dev)
    trace_on(dev)
    xfer_write32(dev, TPIU_SPPR, [TPIU_SPPR_TXMODE_NRZ])
    xfer_write32(dev, TPIU_FFCR, [0]) # Disable tpiu formatting
    xfer_write32(dev, ITM_LAR, [SCS_LAR_KEY])
    xfer_write32(dev, ITM_TCR, [((1<<16) | ITM_TCR_SYNCENA | ITM_TCR_ITMENA)])
    xfer_write32(dev, ITM_TER, [stim_bits])
    xfer_write32(dev, ITM_TPR, [stim_bits])
    # weird read of SRAM here?
    set_dwt_sync_tap(dev, syncpackets)
    # READ DEBUG REG 0xe000edf0 => 0x01010001
    reg = xfer_read32(dev, DCB_DHCSR, 4)[0]
    print("DCB_DHCSR == %#x" % reg)
    # fixme - again, if this isn't ok, probably need to do something, like start it running or something....



def set_dwt_sync_tap(dev, syncbits):
    """
    Selects the position of the synchronization packet counter tap
on the CYCCNT counter. This determines the
Synchronization packet rate:
00 = Disabled. No Synchronization packets.
01 = Synchronization counter tap at CYCCNT[24]
10 = Synchronization counter tap at CYCCNT[26]
11 = Synchronization counter tap at CYCCNT[28]
For more information see The synchronization packet timer
on page C1-874.
    """
    reg = xfer_read32(dev, DWT_CTRL, 4)[0]
    reg &= ~(3<<10)
    reg |= (syncbits << 10)
    xfer_write32(dev, DWT_CTRL, [reg])

# Both of these return 0x80
# winstlink sets up itm and tpiu unlock stuff too!

def trace_bytes_available(dev):
    #logging.debug("checking for bytes to read")
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_GET_TRACE_NB]
    res = xfer_normal_input(dev, cmd, 2, verbose=False)
    bytes = struct.unpack_from("<H", lame_py(bytearray(res)))[0]
    return bytes

def trace_read(dev, count):
    logging.debug("reading %d bytes of trace buffer", count)
    res = dev.read(STLINK_EP_TRACE, count, 0)
    #print("trace read Received: ", res)
    return res

class Swopy(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.dev = find_stlink()

    def do_swo_start(self, args):
        stimbits = 1
        if args:
            try:
                x = int(args, base=0)
                stimbits = x
            except ValueError:
                print("Invalid stim bits: %s" % (args))
                return

        enable_trace(self.dev, stimbits)

    def do_swo_stop(self, args):
        trace_off(self.dev)

    def do_swo_read(self, args):
        """
        attempt to read from the swo endpoint, x times
        """
        count = 1
        if args:
            try:
                x = int(args)
                count = x
            except ValueError:
                print("Ignoring invalid count of swo reads to attempt")

        for i in range(count):
            x = trace_bytes_available(self.dev)
            if x:
                qq = trace_read(self.dev, x)
                print("got trace bytes (raw)", qq)
                print("trace bytes as chars: ", [chr(x) for x in qq])


    def do_connect(self, args):
        """Connect to the target"""
        dev = self.dev
        v = get_version(dev)
        print(v)
        get_mode(dev)
        leave_state(dev)

        if v.jtag_ver >= 13:
            volts = get_voltage(dev)
            print("Voltage: ", volts)

        enter_state_debug(dev)
        print("Status is: ", status(dev))

    def do_disconnect(self, args):
        leave_state(self.dev)


    def do_run(self, args):
        """ Attempt to start the processor (THIS IS BSUTED?!
        """
        run(self.dev)

    def do_enter_debug(self, args):
        enter_state_debug(self.dev)

    def do_mode(self, args):
        s = get_mode(self.dev)
        print("State is %#x" % s)

    def do_leave_state(self, args):
        leave_state(self.dev)

    def do_version(self, args):
        v = get_version(self.dev)
        print(v)

    def _argparse_two_ints(self, args):
        if not args:
            print("Parsing addr/count pair requires arguments!")
            return
        if args:
            aa = args.split()
            if len(aa) != 2:
                print("raw read mem32 requires 2 arguments: addr count")
                return
            try:
                addr = int(aa[0], base=0)
                count = int(aa[1], base=0)
                return (addr, count)
            except ValueError:
                print("addr and count both need to be integers, or convertible to integers")
                return


    def do_raw_read_debug_reg(self, args):
        reg = int(args, base=0)
        v = xfer_read_debug(self.dev, reg)
        print("register %#x = %d (%#08x)" % (reg, v, v))

    def do_raw_write_debug_reg(self, args):
        tup = self._argparse_two_ints(args)
        if tup:
            v = xfer_write_debug(self.dev, tup[0], tup[1])
            print("write debug returned: ", v)

    def do_raw_read_mem32(self, args):
        """
        Read x bytes from address y
        args: address
              number of _bytes_
        """
        tup = self._argparse_two_ints(args)
        if tup:
            v = xfer_read32(self.dev, tup[0], tup[1])
            print("read32 returned: ", v)

    def do_EOF(self, args):
        return self.do_exit(args)

    def do_exit(self, args):
        leave_state(self.dev)
        s = get_mode(self.dev)
        print("Disconnected with state in %d" % s)
        return True

    def cmdloop(self):
        while True:
            try:
                cmd.Cmd.cmdloop(self)
            except KeyboardInterrupt:
                print(' - interrupted')
                continue
            break


if __name__ == "__main__":
    p = Swopy()
    p.cmdloop()



