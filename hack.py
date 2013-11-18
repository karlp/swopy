__author__ = 'karlp'

import time
import logging
import struct
import sys
import cmd
import usb.core
import usb.util
from magic import *


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
        ver = struct.unpack_from(">H", bytearray(blob[:2]))[0]
        self.vid, self.pid = struct.unpack_from("<HH", bytearray(blob[2:]))

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

def xfer_normal_input(dev, cmd, expected_response_size, verbose=True):
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
    print("Attempting to write %#x to %#x" % (val, reg_addr))
    args = [ord(q) for q in struct.pack("<II", reg_addr, val)]
    cmd.extend(args)
    res = xfer_normal_input(dev, cmd, 2)
    print("Write debug reg returned: ", res)

def xfer_read32(dev, reg_addr, count):
    """
    count is in bytes!
    """
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_READMEM32]
    args = [ord(q) for q in struct.pack("<IH", reg_addr, count)]
    cmd.extend(args)
    res = xfer_normal_input(dev, cmd, count)
    print("readmem32 returned %s", res)
    u32s = struct.unpack("<%dI" % (count/4), res)
    print("readmem32 u32s: %s", u32s)
    return u32s

def xfer_write32(dev, reg_addr, data):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_WRITEMEM32]
    print("Attempting to write %s to %#x (len=%d)" % (data, reg_addr, len(data)))
    args = [ord(q) for q in struct.pack("<IH", reg_addr, len(data))]
    cmd.extend(args)
    xfer_normal_input(dev, cmd, 0)
    out_data = struct.pack("<%dI" % len(data), *data)
    xfer_send_only_raw(dev, out_data)


def xfer_unknown_sync(dev):
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
    adc0, adc1 = struct.unpack_from("<II", bytearray(res))
    print(adc0, adc1)
    assert adc0 != 0
    return 2 * adc1 * (1.2 / adc0)

def get_state(dev):
    res = xfer_normal_input(dev, [STLINK_GET_CURRENT_MODE], 2)
    return res[0]

def leave_state(dev, current):
    cmd = None
    if current == STLINK_MODE_DFU:
        logging.debug("Leaving dfu mode")
        cmd = [STLINK_DFU_COMMAND, STLINK_DFU_EXIT]
    elif current == STLINK_MODE_DEBUG:
        logging.debug("Leaving debug mode")
        cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_EXIT]

    if cmd:
        xfer_normal_input(dev, cmd, 0)
    else:
        logging.debug("Ignoring mode we don't know how to leave/or need to leave")

def enter_state_debug(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_ENTER, STLINK_DEBUG_ENTER_SWD]
    res = xfer_normal_input(dev, cmd, 2)
    print("enter debug state returned: ", res)
    # res[0] should be 0x80
    assert res[0] == 0x80, "enter state failed :("

def reset(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_RESETSYS]
    res = xfer_normal_input(dev, cmd, 2)
    print("reset returned: ", res)

def run(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_RUNCORE]
    res = xfer_normal_input(dev, cmd, 2)
    print("RUn returned ", res)
    return res

def status(dev):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_STATUS]
    res = xfer_normal_input(dev, cmd, 2)
    print("status returned", res)
    if res[0] == 0x80:
        return "RUNNING"
    elif res[0] == 0x81:
        return "HALTED"
    else:
        return "UNKNOWN"

def run2(dev):
    #stlink_usb_write_debug_reg(handle, DCB_DHCSR, DBGKEY|C_DEBUGEN);
    #  f2 35 f0 ed 00 e0 01 00 5f a0 00 00 00 00 00 00
    xfer_write_debug(dev, DCB_DHCSR, DCB_DHCSR_DBGKEY|DCB_DHCSR_C_DEBUGEN)

def trace_off(dev):
    logging.info("Disabling swo tracing")
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_STOP_TRACE_RX]
    res = xfer_normal_input(dev, cmd, 2)
    print("Turn off trace returned: ", res)

def trace_on(dev):
    logging.info("Enabling swo tracing")
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_START_TRACE_RX]
    args = [ord(q) for q in struct.pack("<HI", 4096, 2000000)]
    cmd.extend(args)
    # f240001080841e000000000000000000
    # This is what windows stlink sends:     f2 40 00 10 80 84 1e 00 00 00 00 00 00 00 00 00
    # 16 bit trace size = 0x1000
    # 32bit hz
    res = xfer_normal_input(dev, cmd, 2)
    print("Turn on trace returned: ", res)

def enable_trace(dev):
    reg = xfer_read32(dev, DBGMCU_CR, 4)[0]
    reg |= DBGMCU_CR_DEBUG_TRACE_IOEN
    xfer_write32(dev, DBGMCU_CR, [reg])

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
    bytes = struct.unpack_from("<H", bytearray(res))[0]
    return bytes

def trace_read(dev, count):
    logging.debug("reading %d bytes of trace buffer", count)
    res = dev.read(STLINK_EP_TRACE, count, 0)
    #print("trace read Received: ", res)
    return res

# Can't be run in DFU mode!
# print("Status is: ", status(dev))
def _hacky_init():
    dev = find_stlink()
    s = get_state(dev)
    print("state before", s)
    leave_state(dev, s)
    print("state after", get_state(dev))
    v = get_version(dev)
    print(v)
    s = get_state(dev)
    print("state before", s)
    leave_state(dev, s)
    print("state after", get_state(dev))

    if v.jtag_ver >= 13:
        volts = get_voltage(dev)
        print("Voltage: ", volts)

    enter_state_debug(dev)
    print("Status is: ", status(dev))

def _hacktastical(dev):

    # Next thing stlink-windows does is:
    # This is not critical, but would definitely help if anyone had turned it on :)
    xfer_write_debug(dev, DBGMCU_APB1_FZ, DBGMCU_APB1_FZ_DBG_IWDG_STOP)
    # stlink-windows does WRITE_DEBUG_REG[reg=0xe0042004, value=263(0x107)
    # THis writes a 1 to a reserved bit in the DBGMCU_CR register, thanks ST!
    xfer_write_debug(dev, DBGMCU_CR, DBGMCU_CR_DEBUG_SLEEP | DBGMCU_CR_DEBUG_STANDBY | DBGMCU_CR_DEBUG_STOP | DBGMCU_CR_RESERVED_MAGIC_UNKNOWN)
    # Then WRITE_DEBUG_REG[reg=0xe000edf0, value=2690580483(0xa05f0003)]
    xfer_write_debug(dev, DCB_DHCSR, DCB_DHCSR_DBGKEY | DCB_DHCSR_C_HALT | DCB_DHCSR_C_DEBUGEN)
    # READ_DEBUG_REG[reg=0xe000edf0]  ==> 0x03030003
    # WRITE_DEBUG_REG[reg=0xe000edf0, value=2690580483(0xa05f0003)]
    # no idea why it needed a second turn?
    # READ_DEBUG_REG[reg=0xe000edf0]  ==> 0x00030003  ==> confirms it's halted, no resets, no retired insructions
    # WRITE_DEBUG_REG[reg=0xe000edfc, value=1(0x1)]
    xfer_write_debug(dev, DCB_DEMCR, DCB_DEMCR_VC_CORERESET) # enables vector catch?!
    # WRITE_DEBUG_REG[reg=0xe000ed0c, value=100270084(0x5fa0004)]  # clears all state info for exceptions.. useful for getting out of lockup I guess?
    xfer_write_debug(dev, SCS_AIRCR, SCS_AIRCR_KEY | SCS_AIRCR_VECTCLRACTIVE)
    # READ_DEBUG_REG[reg=0xe000ed0c] ==> fa050000
    # READ_DEBUG_REG[reg=0xe000edf0] ==> 0x02030003  ==> one reset since last read, who cares...
    # READ_DEBUG_REG[reg=0xe000edf0] ==> 0x00030003  ==> boring...
    # WRITE_REG[reg=0x10, value=1(0x1)]  ==> ?!
    # WRITE_DEBUG_REG[reg=0xe000edfc, value=0(0x0)]
    xfer_write_debug(dev, DCB_DEMCR, 0)  # Disables vector catch again?!
    # READMEM32[addr=0xe000ed00] ==> read CPUID register, we don't care...
    # then the 0xf2, 3e . ==*> 0x80 and lots of 0s
    xfer_unknown_sync(dev)
    # READMEM32[addr=0xe0042000]  ==> read DBGMCU_IDCODE, we don't care...
    xfer_unknown_sync(dev)
    # reads dbgmcu_idcode again, don't care
    # READMEM32[addr=0x1ff8004c]  ==> reads appropriate flash size register
    xfer_unknown_sync(dev)
    # get target voltage
    # READ_DEBUG_REG[reg=0xe000edf0] == > boring.. DHCSR reads again
    # READMEM32[addr=0xe0042000] ==> read DBGMCU_IDCODE again!
    xfer_unknown_sync(dev)
    # It just sits there doing read IDCODE, send sync thing, over and over again
    # for maybe 20-30 loops or more
    # READ_DEBUG_REG[reg=0xe000edf0] ==> DHCSR again

    # WRITEMEM32[addr=0xe000edfc, len=4(0x4)], data = 00 00 00 01 (No idea what endian that is)
    # also, it does it via a writemem32, not a write_debug_reg?!
    # Probably enabling vector catch again?!
    xfer_unknown_sync(dev)
    # READMEM32[addr=0x20000000, length=4] => 00 36 6e 01 stack pointer right? Reading first bytes of ram
    xfer_unknown_sync(dev)
    # READMEM32[addr=0xe0042004, len=4(0x4)]  ==> read DBGMCU_CR  ==> 0x107 => reserved bit still set
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0042004, len=4(0x4)] ==> 0x127
    # This does a DBGMCU_CR |= TRACE_IOEN
    enable_trace(dev)
    # WRITEMEM32[addr=0xe0040004, len=4(0x4)] ==> 1 => TPIU_CSPSR = 1
    xfer_write32(dev, TPIU_CSPSR, [1])
    # WRITEMEM32[addr=0xe0040010, len=4(0x4)] ==> 0x0b => TPIU_ACPR = 0xb
    xfer_write32(dev, TPIU_ACPR, [0xb])
    xfer_unknown_sync(dev)
    trace_off(dev)
    trace_on(dev)
    # WRITEMEM32[addr=0xe00400f0, len=4(0x4)] => 2 => TPIU_SPPR mode = NRZ
    xfer_write32(dev, TPIU_SPPR, [TPIU_SPPR_TXMODE_NRZ])
    # READMEM32[addr=0xe0042000, len=4(0x4)]  ==> read DBGMCU_ID yet again
    xfer_unknown_sync(dev)
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0040304, len=4(0x4)] => 0
    xfer_write32(dev, TPIU_FFCR, [0]) # Disable continuous formatting
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000fb0, len=4(0x4)] => 0000   55 ce ac c5 (little endian?) => ITM_LAR = 0xC5ACCE55
    xfer_write32(dev, ITM_LAR, [SCS_LAR_KEY])
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000e80, len=4(0x4)] => 0x00010005 ==> ITM_TCR = channel 1 << 16 | ITM_TCR_SYNCENA | ITM_TCR_ITMENA
    xfer_write32(dev, ITM_TCR, [(1<<16 | ITM_TCR_SYNCENA | ITM_TCR_ITMENA)])
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000e00, len=4(0x4)] => 1 => ITM_TER = 1
    xfer_write32(dev, ITM_TER, [1])
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000e40, len=4(0x4)] => 1 => ITM_TPR = 1
    xfer_write32(dev, ITM_TPR, [1])
    xfer_unknown_sync(dev)
    # READMEM32[addr=0x20000000, len=4(0x4)]  ==> who cares....
    # sync
    # READMEM32[addr=0xe0001000, len=4(0x4)] ==> read DWT_CTRL => 0x40000001 ==> 4 comparators, cyc count enabled
    # sync
    # WRITEMEM32[addr=0xe0001000, len=4(0x4)] = 0x40000401 => SYNCTAP 01 = Synchronization counter tap at CYCCNT[24]
    set_dwt_sync_tap(dev, 1)
    xfer_unknown_sync(dev)
    # READ_DEBUG_REG[reg=0xe000edf0] => 0x00030003 BORING DHCSR again
    # WRITE_DEBUG_REG[reg=0xe000edf0, value=2690580481(0xa05f0001)]
    xfer_write_debug(dev, DCB_DHCSR, DCB_DHCSR_DBGKEY | DCB_DHCSR_C_DEBUGEN)

    for i in range(120):
        print("attempting tracebytesavailable(): " , i)
        x = trace_bytes_available(dev)
        if x:
            qq = trace_read(dev, x)
            print("got trace bytes", qq)
            xfer_unknown_sync(dev)
        time.sleep(0.2)

    # READMEM32[addr=0xe0042000, len=4(0x4)] read DBGMCU_ID again
    xfer_unknown_sync(dev)

    # next, a few sequences of trace_bytes_available()()()()
    xfer_unknown_sync(dev)
    # READMEM32[addr=0xe0042000, len=4(0x4)] yet more reading of DBG_MCU
    # then more tracebytes_avaiable() calls a few times...

    #lots of tracebytes_available, interspersed with sync() and reading DBGMCU_ID

    # it was out of sync, and I pushed stop/start from stlink...
    trace_off(dev)
    # sync, read DBGMCU_ID again.  seems to just be what it does when idle....

    # frame 5195, READ_DEBUG_REG[reg=0xe000edf0] read DHCSR again!
    # WRITEMEM32[addr=0xe000edfc, len=4(0x4)] => 0x01000000 ==> DCB_DEMCR = DCB_DEMCR_TRCENA
    xfer_write32(dev, DCB_DEMCR, [DCB_DEMCR_TRCENA])
    xfer_unknown_sync(dev)
    # READMEM32[addr=0x20000000, len=4(0x4)] ==> who cares
    xfer_unknown_sync(dev)
    # READMEM32[addr=0xe0042004, len=4(0x4)] => read DBGMCU_CR == 0x127 (from earlier)
    # WRITEMEM32[addr=0xe0042004, len=4(0x4)] => 0x127
    enable_trace(dev)
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0040004, len=4(0x4)]
    xfer_write32(dev, TPIU_CSPSR, [1])
    # WRITEMEM32[addr=0xe0040010, len=4(0x4)] = 0xb
    xfer_write32(dev, TPIU_ACPR, [0xb])
    xfer_unknown_sync(dev)
    trace_off(dev)
    trace_on(dev)
    # WRITEMEM32[addr=0xe00400f0, len=4(0x4)] = 2
    xfer_write32(dev, TPIU_SPPR, [TPIU_SPPR_TXMODE_NRZ])
    # READMEM32[addr=0xe0042000, len=4(0x4)] read DBGMCU_ID again
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0040304, len=4(0x4)]
    xfer_write32(dev, TPIU_FFCR, [0]) # Disable continuous formatting
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000fb0, len=4(0x4)]
    xfer_write32(dev, ITM_LAR, [SCS_LAR_KEY])
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000e80, len=4(0x4)]
    xfer_write32(dev, ITM_TCR, [(1<<16 | ITM_TCR_SYNCENA | ITM_TCR_ITMENA)])
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000e00, len=4(0x4)]
    xfer_write32(dev, ITM_TER, [1])
    xfer_unknown_sync(dev)
    # WRITEMEM32[addr=0xe0000e40, len=4(0x4)]
    xfer_write32(dev, ITM_TPR, [1])
    xfer_unknown_sync(dev)
    # READMEM32[addr=0x20000000, len=4(0x4)] ==> pointless read of memory
    xfer_unknown_sync(dev)
    # READMEM32[addr=0xe0001000, len=4(0x4)] => read DWT_CTRL => 0x40000401
    # WRITEMEM32[addr=0xe0001000, len=4(0x4)] = synctap 24 again...
    set_dwt_sync_tap(dev, 1)
    xfer_unknown_sync(dev)
    #READ_DEBUG_REG[reg=0xe000edf0] == read DHCSR, because it's fun ==> 0x01010001
    #READMEM32[addr=0xe0042000, len=4(0x4)] read DBGMCU_ID again
    xfer_unknown_sync(dev)

    for i in range(120):
        print("attempting tracebytesavailable(): " , i)
        x = trace_bytes_available(dev)
        if x:
            qq = trace_read(dev, x)
            print("got trace bytes", qq)
            xfer_unknown_sync(dev)
        time.sleep(0.1)

    # from here a regular sequence of trace_bytes_available() mixed with sync() and read dbgmcuid
    # Came back in to proper sync here
    # 0000000000800131
    # 000000000080
    # 0132
    # 000000000080
    # 000000000080
    # 0133
    # 000000000080
    # 0134000000000080
    #

    # Frame 5935 turning off trace again
    trace_off(dev)
    # read dbgmcu_id again..

#dev = _hacky_init()
#_hacktastical(dev)




#
## with trace on, windows st link polls 0xf2, 42 on regular, to get two bytes back, which is the number of trace bytes ready to be read.




# reset?!
#print("Status is (before reset): ", status(dev))
#reset(dev)
#print("Status is (after reset): ", status(dev))

#run2(dev) # RUN DAMN YOU!
#run(dev)
#
#trace_off(dev)
#trace_on(dev)
#should_exit = False
#while not should_exit:
#    try:
#        cnt = trace_bytes_available(dev)
#        if s:
#            r = trace_read(dev, cnt)
#            print("Got tracebytes: ", r)
#        time.sleep(0.5)
#    except KeyboardInterrupt:
#        should_exit = True
#

class Swopy(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.dev = find_stlink()


    def do_swo_start(self, args):
        dev = self.dev
        xfer_write_debug(dev, DBGMCU_APB1_FZ, DBGMCU_APB1_FZ_DBG_IWDG_STOP)
        # stlink-windows does WRITE_DEBUG_REG[reg=0xe0042004, value=263(0x107)
        # THis writes a 1 to a reserved bit in the DBGMCU_CR register, thanks ST!
        xfer_write_debug(dev, DBGMCU_CR, DBGMCU_CR_DEBUG_SLEEP | DBGMCU_CR_DEBUG_STANDBY | DBGMCU_CR_DEBUG_STOP | DBGMCU_CR_RESERVED_MAGIC_UNKNOWN)
        # Then WRITE_DEBUG_REG[reg=0xe000edf0, value=2690580483(0xa05f0003)]
        xfer_write_debug(dev, DCB_DHCSR, DCB_DHCSR_DBGKEY | DCB_DHCSR_C_HALT | DCB_DHCSR_C_DEBUGEN)
        # READ_DEBUG_REG[reg=0xe000edf0]  ==> 0x03030003
        # WRITE_DEBUG_REG[reg=0xe000edf0, value=2690580483(0xa05f0003)]
        # no idea why it needed a second turn?
        # READ_DEBUG_REG[reg=0xe000edf0]  ==> 0x00030003  ==> confirms it's halted, no resets, no retired insructions
        # WRITE_DEBUG_REG[reg=0xe000edfc, value=1(0x1)]
        xfer_write_debug(dev, DCB_DEMCR, DCB_DEMCR_VC_CORERESET) # enables vector catch?!
        # WRITE_DEBUG_REG[reg=0xe000ed0c, value=100270084(0x5fa0004)]  # clears all state info for exceptions.. useful for getting out of lockup I guess?
        xfer_write_debug(dev, SCS_AIRCR, SCS_AIRCR_KEY | SCS_AIRCR_VECTCLRACTIVE)
        # READ_DEBUG_REG[reg=0xe000ed0c] ==> fa050000
        # READ_DEBUG_REG[reg=0xe000edf0] ==> 0x02030003  ==> one reset since last read, who cares...
        # READ_DEBUG_REG[reg=0xe000edf0] ==> 0x00030003  ==> boring...
        # WRITE_REG[reg=0x10, value=1(0x1)]  ==> ?!
        # WRITE_DEBUG_REG[reg=0xe000edfc, value=0(0x0)]
        xfer_write_debug(dev, DCB_DEMCR, 0)  # Disables vector catch again?!
        # READMEM32[addr=0xe000ed00] ==> read CPUID register, we don't care...
        # then the 0xf2, 3e . ==*> 0x80 and lots of 0s
        xfer_unknown_sync(dev)
        # READMEM32[addr=0xe0042000]  ==> read DBGMCU_IDCODE, we don't care...
        xfer_unknown_sync(dev)
        # reads dbgmcu_idcode again, don't care
        # READMEM32[addr=0x1ff8004c]  ==> reads appropriate flash size register
        xfer_unknown_sync(dev)
        # get target voltage
        # READ_DEBUG_REG[reg=0xe000edf0] == > boring.. DHCSR reads again
        # READMEM32[addr=0xe0042000] ==> read DBGMCU_IDCODE again!
        xfer_unknown_sync(dev)
        # It just sits there doing read IDCODE, send sync thing, over and over again
        # for maybe 20-30 loops or more
        # READ_DEBUG_REG[reg=0xe000edf0] ==> DHCSR again

        # WRITEMEM32[addr=0xe000edfc, len=4(0x4)], data = 00 00 00 01 (No idea what endian that is)
        # also, it does it via a writemem32, not a write_debug_reg?!
        # Probably enabling vector catch again?!
        xfer_unknown_sync(dev)
        # READMEM32[addr=0x20000000, length=4] => 00 36 6e 01 stack pointer right? Reading first bytes of ram
        xfer_unknown_sync(dev)
        # READMEM32[addr=0xe0042004, len=4(0x4)]  ==> read DBGMCU_CR  ==> 0x107 => reserved bit still set
        xfer_unknown_sync(dev)
        # WRITEMEM32[addr=0xe0042004, len=4(0x4)] ==> 0x127
        # This does a DBGMCU_CR |= TRACE_IOEN
        enable_trace(dev)
        # WRITEMEM32[addr=0xe0040004, len=4(0x4)] ==> 1 => TPIU_CSPSR = 1
        xfer_write32(dev, TPIU_CSPSR, [1])
        # WRITEMEM32[addr=0xe0040010, len=4(0x4)] ==> 0x0b => TPIU_ACPR = 0xb
        xfer_write32(dev, TPIU_ACPR, [0xb])
        xfer_unknown_sync(dev)
        trace_off(dev)
        trace_on(dev)
        # WRITEMEM32[addr=0xe00400f0, len=4(0x4)] => 2 => TPIU_SPPR mode = NRZ
        xfer_write32(dev, TPIU_SPPR, [TPIU_SPPR_TXMODE_NRZ])
        # READMEM32[addr=0xe0042000, len=4(0x4)]  ==> read DBGMCU_ID yet again
        xfer_unknown_sync(dev)
        xfer_unknown_sync(dev)
        # WRITEMEM32[addr=0xe0040304, len=4(0x4)] => 0
        xfer_write32(dev, TPIU_FFCR, [0]) # Disable continuous formatting
        xfer_unknown_sync(dev)
        # WRITEMEM32[addr=0xe0000fb0, len=4(0x4)] => 0000   55 ce ac c5 (little endian?) => ITM_LAR = 0xC5ACCE55
        xfer_write32(dev, ITM_LAR, [SCS_LAR_KEY])
        xfer_unknown_sync(dev)
        # WRITEMEM32[addr=0xe0000e80, len=4(0x4)] => 0x00010005 ==> ITM_TCR = channel 1 << 16 | ITM_TCR_SYNCENA | ITM_TCR_ITMENA
        xfer_write32(dev, ITM_TCR, [(1<<16 | ITM_TCR_SYNCENA | ITM_TCR_ITMENA)])
        xfer_unknown_sync(dev)
        # WRITEMEM32[addr=0xe0000e00, len=4(0x4)] => 1 => ITM_TER = 1
        xfer_write32(dev, ITM_TER, [1])
        xfer_unknown_sync(dev)
        # WRITEMEM32[addr=0xe0000e40, len=4(0x4)] => 1 => ITM_TPR = 1
        xfer_write32(dev, ITM_TPR, [1])
        xfer_unknown_sync(dev)
        # READMEM32[addr=0x20000000, len=4(0x4)]  ==> who cares....
        # sync
        # READMEM32[addr=0xe0001000, len=4(0x4)] ==> read DWT_CTRL => 0x40000001 ==> 4 comparators, cyc count enabled
        # sync
        # WRITEMEM32[addr=0xe0001000, len=4(0x4)] = 0x40000401 => SYNCTAP 01 = Synchronization counter tap at CYCCNT[24]
        set_dwt_sync_tap(dev, 1)
        xfer_unknown_sync(dev)
        # READ_DEBUG_REG[reg=0xe000edf0] => 0x00030003 BORING DHCSR again
        # WRITE_DEBUG_REG[reg=0xe000edf0, value=2690580481(0xa05f0001)]
        xfer_write_debug(dev, DCB_DHCSR, DCB_DHCSR_DBGKEY | DCB_DHCSR_C_DEBUGEN)


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
                print("got trace bytes", qq)


    def do_connect(self, args):
        """Connect to the target"""
        dev = self.dev
        s = get_state(dev)
        print("state before", s)
        leave_state(dev, s)
        print("state after", get_state(dev))
        v = get_version(dev)
        print(v)
        s = get_state(dev)
        print("state before", s)
        leave_state(dev, s)
        print("state after", get_state(dev))

        if v.jtag_ver >= 13:
            volts = get_voltage(dev)
            print("Voltage: ", volts)

        enter_state_debug(dev)
        print("Status is: ", status(dev))

    def do_quit(self, args):
        return True

    def do_disconnect(self, args):
        pass

    def do_halt(self, args):
        pass

    def do_run(self, args):
        """ Attempt to start the processor
        """
        run(self.dev)

if __name__ == "__main__":
    p = Swopy()
    p.cmdloop()



