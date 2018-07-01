# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

__author__ = 'lem'

KNX_NET_IP_SIGNATURE = '0610'  # typical for start KNXnetIP frame

# Description Field Frame KNX
description_field_knx = {
    # Service Type ID Code Description
    'service_type_id': {
        0x201: 'SEARCH REQUEST',
        0x202: 'SEARCH RESPONSE',
        0x203: 'DESCRIPTION REQUEST',
        0x204: 'DESCRIPTION RESPONSE',
        0x205: 'CONNECTION REQUEST',
        0x206: 'CONNECTION RESPONSE',
        0x207: 'CONNECTION STATE REQUEST',
        0x208: 'CONNECTION STATE RESPONSE',
        0x209: 'DISCONNECT REQUEST',
        0x20A: 'DISCONNECT RESPONSE',

        0x310: 'DEVICE CONFIGURATION REQUEST',
        0x311: 'DEVICE CONFIGURATION_ACK',

        0x420: 'TUNNEL REQUEST',
        0x421: 'TUNNEL RESPONSE',

        0x530: 'ROUTING INDICATION'
    },

    # Message Code Description
    'MsgCode': {
        0x8: 'inknow Msg Code',
        0x29: 'L_DATA_ind',
        0x2E: 'L_DATA_con',
        0x11: 'L_DATA_req',
        0x10: 'L_Raw_req'
    },

    # APDU Code Description
    'APDU': {
        0x0: "Open connection",
        0x1: "Terminate/broken connection",
        0x2: "Pos confirm previously",
        0x3: "Negative confirm previously"
    },

    # Control Field TP Code Description
    'CtrlFieldTP': {
        0x80: "Standart frame",
        0x20: "Do not repeat",
        0x10: "Broadcast",
        0x4: "Normal Priority",
        0x8: "Alarm Priority",
        0xC: "Low Priority"
    },

    # APCI Code Description
    'APCI': {
        0x0: 'Request Group Value Read',
        0x1: 'Group Value Response',
        0x2: 'Group Value Write',
        0x3: 'Individual Addr Write',
        0x4: 'Request Individual Addr Request',
        0x5: 'Individual Addr Response',
        0x6: 'Request ADC Read',
        0x7: 'ADC Response',
        0x8: 'Request Memory Read',
        0x9: 'Memory Response',
        0xA: 'Memory Write',
        0xB: 'UserMessage',
        0xC: 'Request Mask Version Read',
        0xD: 'Mask Version Response',
        0xE: 'Restart',
        0xF: 'Escape'
    },

    # APCI ext Bit Code Description
    'APCI_extBit': {
        0x0: 'Inknow ext bit 0x0',
        0x1: 'Inknow ext bit 0x1',
        0x2: 'Inknow ext bit 0x2',
        0x3: 'Inknow ext bit 0x3',
        0x9: 'Inknow ext bit 0x9',
        0xA: 'Inknow ext bit 0xA',
        16: 'M_Bit Write',                  # 010 000
        17: 'M Authorize Request',          # 010 001
        18: 'M Authorize Response',         # 010 010
        19: 'M Set Key Request',            # 010 011
        20: 'M Set Key Response',           # 010 100
        0x15: 'Request Value System ID',    # 010 101
        0x16: 'Response Value System ID',   # 010 110
        0x17: 'Unknown APCI ext bit code',
        0x18: 'Request Description',        # 011 000
        0x19: 'Response Description'        # 011 001
    },

    # TPCI Code Description
    'TPCI': {
        0: "Unnumbered Data Packet",
        1: "Numbered   Data Packet",
        2: "Unnumbered Control Data",
        3: "Numbered Control Data"
    },

    # Medium
    'Medium': {
        0: 'TP1',
        1: 'PL110',
        2: 'RF',
        5: 'KNXnetIP'
    },

    # Software profile
    'SoftwareProfile':
        {
            0x01: 'System 1 (BCU1)',
            0x02: 'System 2 (BCU2)',
            0x70: 'System 7 (BIM M 112)',
            0x7b: 'System B',
            0x30: 'LTE',
            0x91: 'TP1 Line/area coupler - Repeater',
            0x90: 'Media coupler TP1-PL110'
        }
}

SERVICE_TYPE_ID_SEARCH_REQUEST                = 0x0201
SERVICE_TYPE_ID_SEARCH_RESPONSE               = 0x0202
SERVICE_TYPE_ID_DESCRIPTION_REQUEST           = 0x0203
SERVICE_TYPE_ID_DESCRIPTION_RESPONSE          = 0x0204
SERVICE_TYPE_ID_CONNECTION_REQUEST            = 0x0205
SERVICE_TYPE_ID_CONNECTION_RESPONSE           = 0x0206
SERVICE_TYPE_ID_CONNECTIONSTATE_REQUEST       = 0x0207
SERVICE_TYPE_ID_CONNECTIONSTATE_RESPONSE      = 0x0208
SERVICE_TYPE_ID_DISCONNECT_REQUEST            = 0x0209
SERVICE_TYPE_ID_DISCONNECT_RESPONSE           = 0x020A
SERVICE_TYPE_ID_TUNNEL_REQUEST                = 0x0420
SERVICE_TYPE_ID_TUNNEL_RESPONSE               = 0x0421
SERVICE_TYPE_ID_DEVICE_CONFIGURATION_REQUEST  = 0x0310
SERVICE_TYPE_ID_DEVICE_CONFIGURATION_ACK      = 0x0311
SERVICE_TYPE_ID_ROUTING_INDICATION            = 0x0530

MSG_CODE_L_DATA_IND = 0x29
MSG_CODE_L_DATA_CON = 0x2E
MSG_CODE_L_DATA_REQ = 0x11
MSG_CODE_L_RAW_REQ = 0x10

FLAG_ADDR_TYPE_INDIVIDUAL_ADDRESS = 0x0  # individual address ( 7 bit N_PDU, 5 Octet)
FLAG_ADDR_TYPE_GROUP_ADDRESS = 0x1  # group address      ( 7 bit N_PDU, 5 Octet)

#####################################
#       Flag control field TP       #
#####################################
CTRL_FIELD_TP = 0x90    # 10R1 PP00
                        # R = 0 - repeated telegram
                        # R = 1 - not repeated telegram
                        # PP - sending priority
                        # 00 - System function
                        # 10 - Alarm
                        # 01 - Normal mode high priority
                        # 11 - Normal mode low priority


FLAG_CTR_FIELD_TP_NOT_REPEAT_T = 0x20
FLAG_CTR_FIELD_TP_ALARM = 0x8
FLAG_CTR_FIELD_TP_HIGH_PRIOR = 0x4
FLAG_CTR_FIELD_TP_LOW_PRIOR = 0xC

#####################################
#       Flag control field IP       #
#####################################
CTRL_FIELD_IP = 0x70    # bit_7 - 0 individual address
                        #       - 1 group address
                        # bit_6...4 - routing counter
                        # 0x70 - max hop count i.e. 7

FLAG_CTRL_FIELD_IP_GROUP_ADDR = 0x80  # group address

#####################################
#           TPCI code               #
#####################################
TPCI_CODE_UDP = 0x0  # Unnumbered Data Packet (UDP)
TPCI_CODE_NDP = 0x4000  # Numbered Data Packet (NDP)
TPCI_CODE_UCD = 0x8000  # Unnumbered Control Data (UCD)
TPCI_CODE_NCD = 0xC000  # Numbered Control Data (NCD)'

APDU_OPEN_CONNECTION  = 0x0
APDU_CLOSE_CONNECTION = 0x1
APDU_POS_CONFIRM      = 0x2
APDU_NEG_CONFIRM      = 0x3

APCI_REQ_GROUP_VALUE_READ     = 0x0
APCI_GROUP_VALUE_RESPONSE     = 0x40
APCI_GROUP_VALUE_WRITE        = 0x80
APCI_INDIVIDUAL_ADDR_WRITE    = 0xC0
APCI_REQ_INDIVIDUAL_ADDR_REQ  = 0x100
APCI_INDIVIDUAL_ADDR_RESPONSE = 0x140
APCI_REQ_ADC_READ             = 0x180
APCI_ADC_RESPONSE             = 0x1C0
APCI_REQ_MEMORY_READ          = 0x200
APCI_MEMORY_RESPONSE          = 0x240
APCI_MEMORY_WRITE             = 0x280
APCI_USER_MESSAGE             = 0x2C0
APCI_REQ_MASK_VERSION_READ    = 0x300
APCI_MASK_VERSION_RESPONSE    = 0x340
APCI_RESTART                  = 0x380
APCI_ESCAPE                   = 0x3C0

APCI_EXT_BIT_M_BIT_WRITE            = 0x10    # 010 000
APCI_EXT_BIT_M_AUTHORIZE_REQ        = 0x11    # 010 001
APCI_EXT_BIT_M_AUTHORIZE_RESPONSE   = 0x12    # 010 010
APCI_EXT_BIT_M_SET_KEY_REQ          = 0x13    # 010 011
APCI_EXT_BIT_M_SET_KEY_RESPONSE     = 0x14    # 010 100
APCI_EXT_BIT_REQ_VALUE_SYSTEM_ID    = 0x15    # 010 101
APCI_EXT_BIT_RESPONSE_VALUE_SYS_ID  = 0x16    # 010 110
APCI_EXT_BIT_UNKNOWN_APCI_CODE      = 0x17
APCI_EXT_BIT_REQ_DESCRIPTION        = 0x18    # 011 000
APCI_EXT_BIT_RESPONSE_DESCRIPTION   = 0x19    # 011 001

