__author__ = 'karlp'

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

STLINK_DEBUG_EXIT = 0x21
STLINK_DEBUG_APIV2_START_TRACE_RX = 0x40
STLINK_DEBUG_APIV2_STOP_TRACE_RX = 0x41
STLINK_DEBUG_APIV2_GET_TRACE_NB =0x42


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

def trace_off(dev):
    logging.info("Disabling swo tracing")
    msg = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_STOP_TRACE_RX]
    count = dev.write(STLINK_EP_RX, msg, 0)
    assert count == len(msg)

def trace_on(dev):
    logging.info("Enabling swo tracing")
    msg = [STLINK_DEBUG_COMMAND, STLINK_DEBUG_APIV2_START_TRACE_RX]
    count = dev.write(STLINK_EP_RX, msg, 0)
    assert count == len(msg)

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

def xfer_normal_input(dev, cmd, expected_response_size):
    msg = stlink_pad(cmd)
    print("Sending msg: ", msg)
    count = dev.write(STLINK_EP_TX, msg, 0)
    assert count == len(msg), "Failed to write cmd to usb"
    if expected_response_size:
        res = dev.read(STLINK_EP_RX, expected_response_size, 0)
        print("Received: ", res)
        return res


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

v = get_version(dev)
print(v)
s = get_state(dev)
print("state before", s)
leave_state(dev, s)
print("state after", get_state(dev))

if v.jtag_ver >= 13:
    volts = get_voltage(dev)
    print("Voltage: ", volts)


