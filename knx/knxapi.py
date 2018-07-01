# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

__author__ = 'lem'

import socket

import knxcore

def sniff(type_medium=None, broadcast=None, timeout=45):
    """
    Listen broadcast and show KNXnetIP pkt
    :param type_medium:         type of medium: tp, ip, pl, rf
    :param broadcast:           'IP:port' for broadcast KNXnetIP '224.0.23.12:3671'
    :param timeout:             value in [sec]
    :return:
    """

    if type_medium is None:
        raise Warning('You should specify the type of medium')


    if type_medium == 'tp':
        pass

    elif type_medium == 'ip':
        node = knxcore.FrameKnxNetIp(broadcast)
        node.udp_socket.settimeout(timeout)

    elif type_medium == 'pl':
        pass

    elif type_medium == 'rf':
        pass

    else:
        raise Warning("Unknown type of medium")

    print "\nStart sniff traffic"
    print "Timeout [sec] = ", timeout

    while True:

        try:
            node.receive_frame()

        except socket.timeout:
            break

        else:
            node.show_pkt_knx_ip()

    print "\nEnded by a timeout"
    del node

