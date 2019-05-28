# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

__author__ = 'lem'

import struct
import socket

from knx import knx_definition


###########################################################
#                 Exception KNX                           #
###########################################################
class KnxException(Exception):
    """
    Base class for KNX Exception
    """

    def __init__(self, msg='KNX Exception'):
        self.msg = msg


# Describe KNX-TP
class FrameKnxTp(object):

    def __init__(self):
        """
        Base class for KNX-TP
        """
        self.ctrl_field_tp = 0      # Control Field of KNX-TP
        self.src_addr = []          # 4 bit area + 4 bit line + 8 bit node  / '1.2.45'
        self.dst_addr = []          # 4 bit area + 4 bit line + 8 bit node
        self.addr_typ = None
        self.NPCI = 0               # hop counter
        self.len_frame_knx_tp = 0   # Length KNX frame
        self.TPCI = None            # Transport layer Protocol Control Information
        self.TPCI_seq_num = None    # sequence number in case NDP/NCD
        self.APDU = None            # Type Msg  Open/Terminate or Positive/Negative Confirm
        self.APCI = None            # Application layer Protocol Control Information
        self.APCI_extBit = None
        self.Data = []

        # # use to show information after cmd "get_device_info"
        # self.knx_addr = []
        # self.mask_version = 0
        # self.order_number = []
        # self.serial_number = []
        # self.hardware_type = []
        # self.bus_voltage = []

    # def _refresh_frame_knx_tp(self):
    #     '''
    #     Refresh self value before decode frame knx-tp
    #     :return:
    #     '''
    #     self.ctrl_field_tp = 0
    #     self.src_addr[:] = []
    #     self.dst_addr[:] = []
    #     self.addr_typ = None
    #     self.NPCI = 0
    #     self.len_frame_knx_tp = 0
    #     self.TPCI = None
    #     self.TPCI_seq_num = None
    #     self.APDU = None
    #     self.APCI = None
    #     self.APCI_extBit = None
    #     self.Data[:] = []

    # def _refresh_info_node(self):
    #     self.knx_addr[:] = []
    #     self.mask_version = 0
    #     self.order_number[:] = []
    #     self.serial_number[:] = []
    #     self.hardware_type[:] = []
    #     self.bus_voltage[:] = []

    def _create_frame_knx_tp(self):
        """
        Create KNX-TP frame without check-sum
        :return: raw string of KNX frame
        """

        frame_knx = ""  # raw  binary string

        len_data = len(self.Data)

        frame_knx += struct.pack('B', self.ctrl_field_tp)  # Octet 0

        if (self.src_addr[0] > 15) or (self.src_addr[1] > 15) or (self.src_addr[2] > 255):
            raise KnxException('[knx-knx]: Src Addr should be "x.y.z", x=[0..15], y=[0..15], z=[0..255]')
        else:
            frame_knx += struct.pack('B', (int(self.src_addr[0]) << 4) | (int(self.src_addr[1])))  # Octet 1 Src Address
            frame_knx += struct.pack('B', int(self.src_addr[2]))                                   # Octet 2 Src Address

        # Select Group or Individual address                                                  # Octet 3/4 Dst Address
        if self.addr_typ is None:
            raise KnxException('[knx-knx]: Need set addr type')

        # Format addr x.y
        if self.addr_typ == 0x1:
            try:
                frame_knx += struct.pack('B', (int(self.dst_addr[0]) << 3) | ((int(self.dst_addr[1]) & 0x700) >> 8))

            except struct.error:
                print("Wrong dst address")
                print("Dst addr should be format x.y, where x=[0..15], y=[0..2047]")
                raise KnxException("[knx-knx]: Dst addr should be format x.y, where x=[0..15], y=[0..2047]")

            else:
                try:
                    frame_knx += struct.pack('B', int(self.dst_addr[1]) & 0xFF)

                except struct.error:
                    print("Wrong dst addr")
                    raise KnxException("[knx-knx]: Dst addr should be format x.y, where x=[0..15], y=[0..2047]")

        # Format addr x.y.z
        else:
            try:
                frame_knx += struct.pack('B', (int(self.dst_addr[0]) << 4) | (int(self.dst_addr[1])))

            except struct.error:
                raise KnxException('[knx-knx]: Wrong dst format x.y.z')

            else:
                try:
                    frame_knx += struct.pack('B', int(self.dst_addr[2]))
                except struct.error:
                    raise KnxException('[knx-knx]: Wrong dst format x.y.z')

        if self.APCI_extBit is not None:
            frame_knx += struct.pack('B', ((self.addr_typ << 7) | 
                                           ((self.NPCI & 0x7) << 4) | 
                                           (len(self.Data) + 1)) & 0xFF)
                                                                        # Octet 5
                                                                        # 7 bit - AT
                                                                        # 6..4 bit - NPCI
                                                                        # 3..0 bit - length KNX TP
                                                                        # used mask 0xFF in case that limits knx message
        else:
            frame_knx += struct.pack('B', ((self.addr_typ << 7) | ((self.NPCI & 0x7) << 4) | len(self.Data)) & 0xFF)

        # in case TPCI = NDP or NCD
        #   01 (0x4000) - Numbered Data Packet
        #   11 (0xC000) - Numbered Control Data
        if self.TPCI == 0x4000 or self.TPCI == 0xC000:
            self.TPCI |= (self.TPCI_seq_num << 10)

        # in case APCI == 'Escape'
        #   1111 - 'Escape'
        if self.APCI == 0x3C0:
            self.APCI |= self.APCI_extBit

        # TPCI
        #   10 - UCD Unnumbered Control Data
        if ((self.TPCI & 0xC000) >> 14) == 2:
            frame_knx += struct.pack('B', (((self.TPCI & 0xFF00) >> 8) | self.APDU) & 0xFF)  # APDU means:
            # UCD (2):
            #   00 open connection
            #   01 terminate connection
            if len_data != 0:
                raise KnxException('[knx-knx]:  Wrong frame format')
            return frame_knx

        # TPCI
        #   11 - Numbered Control Data
        elif ((self.TPCI & 0xC000) >> 14) == 3:
            frame_knx += struct.pack('B', (((self.TPCI & 0xFF00) >> 8) | self.APDU) & 0xFF)  # APDU means:
            # NCD (2):
            #   10 positive confirm
            #   11 negative confirm
            if len_data != 0:
                raise KnxException('[knx-knx]: Wrong frame format')
            return frame_knx

        else:
            frame_knx += struct.pack('B', ((self.TPCI | self.APCI) & 0xFF00) >> 8)  # Octet 6
            #   7...6 bit - TPCI
            #   5...2 bit - seq number in case NDP
            #   1...0 bit - HI 2 bit APCI

            if self.APCI_extBit is not None:
                frame_knx += struct.pack('B', (self.APCI | self.APCI_extBit) & 0xFF)  # Octet 7
                frame_knx += struct.pack('%dB' % len_data, *self.Data)  # Octet 8 ... Data
                return frame_knx

            elif self.APCI == knx_definition.APCI_USER_MESSAGE:
                frame_knx += struct.pack('B', self.APCI & 0xFF)
                frame_knx += struct.pack('%dB' % len(self.Data), *self.Data)
                return frame_knx

            else:
                if self.Data[0] <= 0x3F:
                    frame_knx += struct.pack('B', (self.APCI & 0xFF) | self.Data.pop(0))

                else:
                    frame_knx += struct.pack('B', (self.APCI & 0xFF))

                frame_knx += struct.pack('%dB' % len(self.Data), *self.Data)

                return frame_knx

    def _decode_frame_knx_tp(self, raw_frame):
        """
        Receive raw knx-tp frame and then decode it
        :param raw_frame: list of raw data
        :return:
        """

        # self._refresh_frame_knx_tp()

        # Octet 0
        self.ctrl_field_tp = raw_frame.pop(0)               # Control Field KNX-TP

        # Octet 1-2
        self.src_addr.append((raw_frame[0] & 0xF0) >> 4)    # get Area
        self.src_addr.append(raw_frame.pop(0) & 0xF)        # get Line
        self.src_addr.append(raw_frame.pop(0))              # get Node

        # Octet 3-4
        if ((raw_frame[2] & 0x80) >> 7) == 1:
            self.dst_addr.append((raw_frame[0] & 0x78) >> 3)  # format dst address x.y where x=[0..15] y=[0..2047]
            self.dst_addr.append(((raw_frame.pop(0) & 0x7) << 8) | (raw_frame.pop(0)))
        else:
            self.dst_addr.append((raw_frame[0] & 0xF0) >> 4)    # get Area
            self.dst_addr.append(raw_frame.pop(0) & 0xF)        # get Line
            self.dst_addr.append(raw_frame.pop(0))              # get Node

        # Octet 5
        self.addr_typ = (raw_frame[0] & 0x80) >> 7              # Address Type
                                                                # 1 - Group address telegram
                                                                # 0 - Individual address telegram

        self.NPCI = (raw_frame[0] & 0x70) >> 4                  # NPCI value of the routing counter
                                                                # if NPCI = 0 the frame will be deleted

        self.len_frame_knx_tp = raw_frame.pop(0) & 0xF          # Length KNX TP frame

        self.TPCI = (raw_frame[0] & 0xC0) >> 6                  # TPCI bit 6,7 Type of Communication
                                                                # 0 - UDP (Unnumbered Data Packet)
                                                                # 1 - NDP (Numbered Data Packet)
                                                                # 2 - UCD (Unnumbered Control Data)
                                                                # 3 - NCD (Numbered Control Data)
        # in case
        #   01 - Numbered Data Packets (NDP)
        #   11 - Numbered Control Data (NCD)
        if self.TPCI == 1 or self.TPCI == 3:
            self.TPCI_seq_num = (raw_frame[0] & 0x3C) >> 2

        # in case
        # 10 - Unnumbered Control Data (UCD)
        if self.TPCI == 2:
            self.APDU = raw_frame.pop(0) & 0x3                  # 0 - open communication
                                                                # 1 - terminate/broken down
            if len(raw_frame) > 0:
                raise KnxException('[knx-knx]: There is deviation from specification APDU open/close + data')

        # in case
        # 11 - Numbered Control Data (NCD)
        elif self.TPCI == 3:
            self.APDU = raw_frame.pop(0) & 0x3                  # 2 - positively confirm
                                                                # 3 - negatively confirm
            if len(raw_frame) > 0:
                raise KnxException('[knx-knx]: There is deviation from specification APDU positive/negative + data')

        # in case
        # 00 - Unnumbered Data Packet (UDP)
        # 01 - Numbered Data Packet (NDP)
        else:
            self.APCI = ((raw_frame.pop(0) & 0x3) << 2) | ((raw_frame[0] & 0xC0) >> 6)  # get APCI code

            # APCI == 00 00 Group Value Read Request
            if self.APCI == 0:
                if self.len_frame_knx_tp != 0:
                    self.Data.append(raw_frame.pop() & 0x3F)

            # APCI == 00 01
            # Group Value Response
            elif self.APCI == 1:
                if len(raw_frame) > 1:
                    raw_frame.pop(0)
                    self.Data.extend(raw_frame)
                else:
                    self.Data.append(raw_frame.pop() & 0x3F)

            # APCI == 00 10
            # Group Value Write
            elif self.APCI == 2:
                if len(raw_frame) > 1:
                    raw_frame.pop(0)
                    self.Data.extend(raw_frame)
                else:
                    self.Data.append(raw_frame.pop() & 0x3F)

            # APCI == 00 11
            # Individual Address Write
            elif self.APCI == 3:
                raw_frame.pop(0)
                self.Data.extend(raw_frame)

            # APCI == 01 00
            # Individual Address Request
            elif self.APCI == 4:
                if self.len_frame_knx_tp != 0:
                    self.Data.append(raw_frame.pop() & 0x3F)

            # APCI == 01 01
            # Individual Address Response
            elif self.APCI == 5:
                if self.len_frame_knx_tp != 0:
                    self.Data.append(raw_frame.pop() & 0x3F)

            # APCI == 01 10
            # ADC Read Request
            elif self.APCI == 6:
                self.Data.extend(raw_frame)                 # 1 num - number of ADC chanel to be read
                                                            # 2 num - num ADC conversion to be carried out and summed

            # APCI == 01 11
            # ADC Response
            elif self.APCI == 7:
                self.Data.append(raw_frame.pop() & 0x3F)    # 1 num - number of ADC chanel to be read
                self.Data.extend(raw_frame)                 # 2 num - num ADC conversion to be carried out and summed
                                                            # 3 num - high byte of result
                                                            # 4 num - low byte of result

            # APCI == 10 00
            # Memory Read Request
            elif self.APCI == 8:
                self.Data.append(raw_frame.pop(0) & 0xF)    # 1 num - length of the memory area to be read (bytes)
                self.Data.extend(raw_frame)                 # 2 num - start address high byte
                                                            # 3 num - start address low byte

            # APCI == 10 01
            # Memory Response
            elif self.APCI == 9:
                self.Data.append(raw_frame.pop(0) & 0xF)    # 1 num - length of the memory area to be read (bytes)
                self.Data.extend(raw_frame)                 # 2 num - start address high byte
                                                            # 3 num - start address low byte
                                                            # 4... num - contents of the memory area read

            # APCI == 10 10
            # Memory Write
            elif self.APCI == 10:
                self.Data.append(raw_frame.pop(0) & 0xF)    # 1 num - numbers of bytes to be written
                self.Data.extend(raw_frame)                 # 2 num - start address high byte
                                                            # 3 num - start address low byte
                                                            # 4... num - data to be written

            # APCI == 10 11
            # User Message
            elif self.APCI == 11:
                self.Data.append(raw_frame.pop() & 0x3F)
                self.Data.extend(raw_frame)

            # APCI == 11 00
            # Mask Version Read Request
            elif self.APCI == 12:
                if self.len_frame_knx_tp != 0:
                    self.Data.append(raw_frame.pop() & 0x3F)

            # APCI == 11 01
            # Mask Version Response
            elif self.APCI == 13:
                raw_frame.pop(0)
                self.Data.extend(raw_frame)                 # 1 num - mask type
                                                            # 2 num - mask version

            # APCI == 11 10
            # Restart:
            elif self.APCI == 14:
                if self.len_frame_knx_tp != 0:
                    self.Data.extend(raw_frame)

            # APCI == 11 11
            # Escape
            elif self.APCI == 15:
                self.APCI_extBit = raw_frame.pop(0) & 0x3F
                self.Data.extend(raw_frame)

    def show_info_pkt_knx_tp(self, pkt_tp):
        """
        Show code and description current knx tp frame
        :param pkt_tp: True - frame KNX-TP
                       False - frame KNXnetIP
        :return:
        """

        if pkt_tp:
            print "*** KNX-TP frame *** "

        print "       Control Field TP:                    ", hex(self.ctrl_field_tp)
        print "       Source address:                      ", '.'.join(str(index) for index in self.src_addr)
        print "       Destination address:                 ", '.'.join(str(index) for index in self.dst_addr)
        print "       Address type:                        ", self.addr_typ
        print "       Value of the routing counter (NPCI): ", hex(self.NPCI)
        print "       Len KNX TP frame:                    ", hex(self.len_frame_knx_tp)
        print "       TPCI code:                           ", hex(self.TPCI)
        print "                 %s" % knx_definition.description_field_knx['TPCI'][self.TPCI]

        if self.TPCI_seq_num is not None:
            print "       TPCI sequence number (NDP, NCD):     ", hex(self.TPCI_seq_num)

        if self.TPCI == 2 or self.TPCI == 3:
            print "       APDU code:                           ", hex(self.APDU)
            print "                  %s" % knx_definition.description_field_knx['APDU'][self.APDU]

        if self.APCI is not None:
            print "       APCI code:                           ", hex(self.APCI)
            print "                  %s" % knx_definition.description_field_knx['APCI'][self.APCI]

        if self.APCI_extBit is not None:
            print "       APCI ext Bit code:                   ", hex(self.APCI_extBit)
            print "                         %s" % knx_definition.description_field_knx['APCI_extBit'][self.APCI_extBit]

        if len(self.Data) > 0:
            print "       Data:                                ", self.Data
        print " **************************************"

    def send_frame(self):
        """
        Send frame via KNX-TP
        :return:
        """
        print "Will be realized in future"
        pass

    def receive_frame(self):
        """
        Receive frame from KNX-TP
        :return:
        """
        print "Will be realized in future"

    # def refresh_frame(self, type_frame):
    #     """
    #     Refresh frame
    #     :param type_frame:    'tp' - to refresh knx-tp
    #     :return:
    #     """
    #     if type_frame == 'tp':
    #         self._refresh_frame_knx_tp()
    #     elif type_frame == 'info':
    #         self._refresh_info_node()
    #         self._refresh_frame_knx_tp()


# Describe KNXnet/IP
class FrameKnxNetIp(FrameKnxTp):

    def __init__(self, knx_broadcast=None):
        FrameKnxTp.__init__(self)
        self.header_length      = 0x6       # Header Length, typical 0x6,                     size 8 bit / 1 byte
        self.protocol_version   = 0x10      # Protocol Version, current 1.0 but value 0x10     1 byte
        self.service_type_id    = 0         # Service Type Identifier                         size 16 bit / 2 byte
        self.len_frame_knx_ip   = 0         # Total Length                                    size 16 bit / 2 byte
        self.message_code       = 0         #                                                 size 8 bit  / 1 byte
        self.add_info_len       = 0         # Additional information length, typical value 0
        self.ctrl_field_ip      = 0

        if knx_broadcast is None:
            knx_broadcast = knx_definition.KNX_BROADCAST

        host, port = knx_broadcast.split(':')                               # configure socket to receive broadcast msg
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind(('', int(port)))
        cfg_broadcast = struct.pack('=4sl', socket.inet_aton(host), socket.INADDR_ANY)

        try:
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, cfg_broadcast)
        except socket.error:
            print '\n     Warning !!!'
            print "It does not support the functionality associated with Rx and Tx KNXnetIP"

        # # use for some KNXnetIP cmd
        # self.hpai_len = 0  #
        # self.hpai_host_protocol = 0  # 0x1 - UDP
        # self.hpai_ip_port = ""  # host ip:port
        # self.hpai_knx_broadcast = ""
        # self.hpai_mac = []
        # self.hpai_friendly_name = ""

    def __del__(self):
        """
        Close socket when object deleted
        :return:
        """
        self.udp_socket.close()

    # def _refresh_frame_knx_ip(self):
    #     """
    #     Refresh self value before decode frame knx-ip
    #     :return:
    #     """
    #     self.header_length = 0
    #     self.protocol_version = 0
    #     self.service_type_id = 0
    #     self.len_frame_knx_ip = 0
    #     self.message_code = 0
    #     self.add_info_len = 0
    #     self.ctrl_field_ip = 0
    #
    #     self._refresh_frame_knx_tp()

    def _create_frame_knx_ip(self):
        """
        Create raw frame KNXnetIP
        :return: [len_KNXnetIP, payload]
        """

        payload = ""

        frame_tp = self._create_frame_knx_tp()

        frame_tp = frame_tp[0] + struct.pack('B', self.ctrl_field_ip) + frame_tp[1:]

        clear_N_PDU = list(struct.unpack('%dB' % len(frame_tp), frame_tp[:]))
        clear_N_PDU[6] &= 0xF                               # Clear first 4 bits in N_PDU i.e

        frame_tp = struct.pack('%dB' % len(clear_N_PDU), *clear_N_PDU)

        payload += struct.pack('B', self.header_length)     # Header length, constant, typical value 0x6
        payload += struct.pack('B', self.protocol_version)  # Protocol version, current 0x10 = version 1

        payload += struct.pack('>H', self.service_type_id)  # Service type ID, size 2 bytes
        payload += '\x00'                                   # Total length HI byte
        payload += '\x00'                                   # Total length Low byte

        payload += struct.pack('B', self.message_code)      # Message Code
                                                            # 0x29 L_DATA.ind
                                                            # 0x2E L_DATA.con
                                                            # 0x11 L_DATA.req

        payload += struct.pack('B', self.add_info_len)      # Additional Info length, typical value = 0

        payload += frame_tp

        len_knxnet_ip = len(payload)

        payload = payload[0:4] + struct.pack('>H', len_knxnet_ip) + payload[6:]

        return [len_knxnet_ip, payload]

    def _action_knxnetip_core(self, raw_frame):
        """
        Decode KNXnet/IP frame in case action KNXnet/IP Core
        :param raw_frame: received raw_frame, type list
        :return:
        """

        # decode SEARCH REQUEST
        if self.service_type_id == 0x201:
            self.hpai_len = raw_frame.pop(0)
            self.hpai_host_protocol = raw_frame.pop(0)
            self.hpai_ip_port = '.'.join(str(i) for i in raw_frame[0:4]) + \
                                ':' + \
                                str((raw_frame[4] << 8) | raw_frame[5])
            del raw_frame[0:5]

        # decode SEARCH RESPONSE
        elif self.service_type_id == 0x202:
            self.hpai_len = raw_frame.pop(0)
            self.hpai_host_protocol = raw_frame.pop(0)
            self.hpai_ip_port = '.'.join(str(i) for i in raw_frame[0:4]) + \
                                ':' + \
                                str((raw_frame[4] << 8) | raw_frame[5])
            del raw_frame[0:6]  # remove IP:port

            del raw_frame[0:4]

            self.knx_addr.append((raw_frame[0] & 0xF0) >> 4)
            self.knx_addr.append(raw_frame.pop(0) & 0xF)
            self.knx_addr.append(raw_frame.pop(0))

            del raw_frame[0:8]

            self.hpai_knx_broadcast = raw_frame[0:4]  # get broadcast knx
            del raw_frame[0:4]

            self.hpai_mac = raw_frame[0:6]
            del raw_frame[0:6]

            self.hpai_friendly_name = (struct.pack('%dB' % len(raw_frame[0:30]), *raw_frame[0:30])).encode('utf-8')

        else:
            print "Will be realised in future"

    def _action_knxnetip_device_management(self, raw):
        print "action KNXnet/IP Device Management"
        print "HPAI: ", raw
        print ""

    def _action_knxnetip_tunnelling(self, raw):
        print "action KNXnet/IP Tunneling"
        print "HPAI: ", raw
        print ""

    def _action_knxnetip_routing(self, raw_frame):
        """
        Decode KNXnet/IP frame in case action KNXnet/IP Routing
        :param raw_frame:
        :return:
        """

        self.message_code = raw_frame.pop(0)    # Message Code
                                                # 0x29 - L_DATA.ind
                                                # 0x2E - L_DATA.con
                                                # 0x11 - L_DATA.req
        self.add_info_len = raw_frame.pop(0)
        if self.add_info_len != 0:
            print "raw frame: ", raw_frame
            raise KnxException("This frame can't be decode in this version tools")

        self.ctrl_field_ip = raw_frame.pop(1)

        self._decode_frame_knx_tp(raw_frame)

    def _action_knxnetip_remote_logging(self, raw):
        print "action KNXnet/IP Remote Logging"
        print "HPAI: ", raw
        print ""

    def _action_knxnetip_remote_configuration(self, raw):
        print "action KNXnet/IP Remote Configuration and Diagnostics"
        print "HPAI: ", raw
        print ""

    def _action_knxnetip_object_server(self, raw):
        print "action KNXnet/IP Object Server"
        print "HPAI: ", raw
        print ""

    def _decode_frame_knx_ip(self, raw):

        # self._refresh_frame_knx_ip()

        len_raw = len(raw)

        raw_frame = list(struct.unpack('!%dB' % len_raw, raw[:]))

        self.header_length = raw_frame.pop(0)                               # Header length, typical 0x6, 1 byte
        self.protocol_version = raw_frame.pop(0)                            # Protocol version, typical 0x10, 1 byte
        self.service_type_id = (raw_frame.pop(0) << 8) | raw_frame.pop(0)   # Service Type ID, 2 bytes
        self.len_frame_knx_ip = (raw_frame.pop(0) << 8) | raw_frame.pop(0)  # Total length KNXnetIP frame, 2 bytes

        if 0x200 <= self.service_type_id <= 0x20F:
            self._action_knxnetip_core(raw_frame)

        elif 0x310 <= self.service_type_id <= 0x31F:
            self._action_knxnetip_device_management(raw_frame)

        elif 0x420 <= self.service_type_id <= 0x42F:
            self._action_knxnetip_tunnelling(raw_frame)

        elif 0x530 <= self.service_type_id <= 0x53F:
            self._action_knxnetip_routing(raw_frame)

        elif 0x600 <= self.service_type_id <= 0x6FF:
            self._action_knxnetip_remote_logging(raw_frame)

        elif 0x740 <= self.service_type_id <= 0x7FF:
            self._action_knxnetip_remote_configuration(raw_frame)

        elif 0x800 <= self.service_type_id <= 0x8FF:
            self._action_knxnetip_object_server(raw_frame)

        else:
            raise KnxException("[knx-knx]: Unknown service type ID")

    # def refresh_frame(self, type_frame):
    #     """
    #     Refresh frame
    #     :param type_frame:  'ip' - to refresh knx-ip
    #     :return:
    #     """
    #     if type_frame == 'ip':
    #         self._refresh_frame_knx_ip()
    #     elif type_frame == 'info':
    #         self._refresh_info_node()
    #         self._refresh_frame_knx_ip()

    def show_pkt_knx_ip(self):
        """
        Show code and description current knx ip frame
        :return:
        """
        print "\n\n                *** KNXnetIP frame ***"
        print "Header"
        print "       Header Length:           ", hex(self.header_length)
        print "       Protocol Ver:            ", hex(self.protocol_version)
        print "       Service Tipe ID:         ", hex(self.service_type_id)
        print "       Total Length:            ", hex(self.len_frame_knx_ip)
        print "cEMI Message Format "
        print "       Message Code:                        ", hex(self.message_code)
        print "                    %s" % knx_definition.description_field_knx['MsgCode'][self.message_code]
        print "       Additional Info Length:              ", hex(self.add_info_len)
        print "       Control Field IP:                    ", hex(self.ctrl_field_ip)
        self.show_info_pkt_knx_tp(False)

    def send_frame(self, ctrl_ip, gateway=None):
        """
        Create frame and if there is not error send this frame via UDP
        :type ctrl_ip:                          # ctrl flag for KNXnetIP structure
        :param gateway:                         # gateway KNXnet/IP to KNX-TP
        :return:
        """

        self.header_length = 0x6
        self.protocol_version = 0x10
        self.service_type_id = knx_definition.SERVICE_TYPE_ID_ROUTING_INDICATION
        self.message_code = knx_definition.MSG_CODE_L_DATA_IND
        self.add_info_len = 0
        self.ctrl_field_ip = ctrl_ip

        if gateway is None:
            raise KnxException('[knx-knx]: Wrong "IP:port" for gateway')

        try:
            frame_knx_ip = self._create_frame_knx_ip()

        except KnxException as e:
            print e.msg

        else:
            host, port = gateway.split(':')
            self.udp_socket.sendto(frame_knx_ip[1], (host, int(port)))

            # self._refresh_frame_knx_ip()

    def receive_frame(self):
        """
        Received KNXnetIP frame from multicast and decode it
        :return:
        """
        raw_knxnetip = self.udp_socket.recv(1024)
        self._decode_frame_knx_ip(raw_knxnetip)

    # def decode_eth_pkt(self, eth_pkt):
    def check_knxnetip_eth_pkt(self, eth_pkt):
        """
        use to read pcap file and store to xls file
        before check eth packet
        typical signature KNXnetIP - '0610'
        :return:
        """
        if hasattr(eth_pkt, 'load') and \
                eth_pkt.load and \
                eth_pkt.load.encode('hex').startswith(knx_definition.KNX_NET_IP_SIGNATURE):
            self._decode_frame_knx_ip(eth_pkt.load)
        else:
            raise KnxException('This packet is not KNXnetIP ')

