__author__ = 'karlp'

import time
import logging
import struct
import usb.core
import usb.util
dev = usb.core.find(idVendor=0x0483, idProduct=0x3748)
#dev = usb.core.find(idProduct="STLINK/V2")

STLINK_EP_TRACE = 0x83
STLINK_EP_TX = 0x2
STLINK_EP_RX = 0x81

STLINK_CMD_SIZE_V2          = 16

STLINK_GET_VERSION             = 0xF1
STLINK_DEBUG_COMMAND           = 0xF2
STLINK_DFU_COMMAND             = 0xF3
STLINK_SWIM_COMMAND            = 0xF4
STLINK_GET_CURRENT_MODE        = 0xF5
STLINK_GET_TARGET_VOLTAGE      = 0xF7

STLINK_MODE_DFU = 0
STLINK_MODE_MASS = 1
STLINK_MODE_DEBUG = 2
STLINK_MODE_SWIM = 3
STLINK_MODE_BOOTLOADER = 4

STLINK_DFU_EXIT = 0x7

STLINK_DEBUG_STATUS                = 0x01
STLINK_DEBUG_RESETSYS              = 0x03 # apiv1 from stlink-texane?!
STLINK_DEBUG_RUNCORE               = 0x09
STLINK_DEBUG_ENTER_SWD             = 0xa3
STLINK_DEBUG_APIV2_ENTER           = 0x30
STLINK_DEBUG_APIV2_RESETSYS        = 0x32
STLINK_DEBUG_APIV2_WRITEDEBUGREG   = 0x35
STLINK_DEBUG_EXIT                  = 0x21
STLINK_DEBUG_APIV2_START_TRACE_RX  = 0x40
STLINK_DEBUG_APIV2_STOP_TRACE_RX   = 0x41
STLINK_DEBUG_APIV2_GET_TRACE_NB    = 0x42

# ARM STUFF
DCB_DHCSR = 0xE000EDF0
DBGKEY = (0xA05F << 16)
C_DEBUGEN = (1<<0)



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

def xfer_write_debug(dev, reg_addr, val):
    cmd = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_WRITEDEBUGREG]
    print("Attempting to write %#x to %#x" % (val, reg_addr))
    args = [ord(q) for q in struct.pack("<II", reg_addr, val)]
    cmd.extend(args)
    res = xfer_normal_input(dev, cmd, 2)
    print("Write debug reg returned: ", res)

def get_version(dev):
    res = xfer_normal_input(dev, [STLINK_GET_VERSION], 6)
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
    xfer_write_debug(dev, DCB_DHCSR, DBGKEY|C_DEBUGEN)

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
    # This is what windows stlink sends:     f2 40 00 10 80 84 1e 00 00 00 00 00 00 00 00 00
    # 16 bit trace size = 0x1000
    # 32bit hz
    res = xfer_normal_input(dev, cmd, 2)
    print("Turn on trace returned: ", res)

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
    print("trace read Received: ", res)
    return res

# Can't be run in DFU mode!
# print("Status is: ", status(dev))
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
#
## with trace on, windows st link polls 0xf2, 42 on regular, to get two bytes back, which is the number of trace bytes ready to be read.

# reset?!
print("Status is (before reset): ", status(dev))
reset(dev)
print("Status is (after reset): ", status(dev))

#run2(dev) # RUN DAMN YOU!
run(dev)
#
trace_off(dev)
trace_on(dev)
should_exit = False
while not should_exit:
    try:
        cnt = trace_bytes_available(dev)
        if s:
            r = trace_read(dev, cnt)
            print("Got tracebytes: ", r)
        time.sleep(0.5)
    except KeyboardInterrupt:
        should_exit = True
#
