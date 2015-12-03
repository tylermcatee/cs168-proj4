import unittest
from firewall import *
import mock
from main import *

deny_tcp_basic_rules = 'test_rules/deny_tcp_basic.conf'

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

class StatefulTests(unittest.TestCase):

    def test_basic_tcp_deny(self):
        rules = Rules(deny_tcp_basic_rules)
        binary_packet = BinaryPacket().get_tcp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        # Just test that we register correctly a deny
        self.assertEqual(RULE_RESULT_DENY, result)

    @mock.patch.object(Firewall, 'inject_rst_pkt')
    def test_firewall_executes_tcp_deny_path(self, mock_inject):
        config = {'rule' : deny_tcp_basic_rules}
        f = Firewall(config, None, None)
        binary_packet = BinaryPacket().get_tcp_packet()
        f.handle_packet(PKT_DIR_INCOMING, binary_packet)
        self.assertTrue(mock_inject.called)

    @mock.patch.object(EthernetInterface, 'send_ip_packet')
    def test_basic_tcp_deny_calls_send_ip_packet(self, mock_send_ip_packet):
        config = {'rule' : deny_tcp_basic_rules}
        f = Firewall(config, iface_int=None, iface_ext=EthernetInterface())
        binary_packet = BinaryPacket().get_tcp_packet()
        f.handle_packet(PKT_DIR_INCOMING, binary_packet)
        # Assert that we called the send_ip_packet method
        self.assertTrue(mock_send_ip_packet.called)

    @mock.patch.object(EthernetInterface, 'send_ip_packet')
    def test_send_ip_packet_contents_incoming(self, mock_send_ip_packet):
        config = {'rule' : deny_tcp_basic_rules}
        f = Firewall(config, iface_int=None, iface_ext=EthernetInterface())
        binary_packet = BinaryPacket().get_tcp_packet()
        f.handle_packet(PKT_DIR_INCOMING, binary_packet)
        # Get the args
        args = mock_send_ip_packet.call_args
        pkt = args[0][0]
        outgoing_packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=pkt, geoDB=None)
        sent_packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        # Should be TCP
        self.assertEqual(socket.IPPROTO_TCP, outgoing_packet.get_protocol())
        # RST Flag should be 1
        self.assertTrue(outgoing_packet.get_rst_flag())
        # Destination should be the source of the packet we sent in
        self.assertEqual(outgoing_packet.get_dst_port(), sent_packet.get_src_port())
        self.assertEqual(outgoing_packet.get_dst_ip(), sent_packet.get_src_ip())

    @mock.patch.object(EthernetInterface, 'send_ip_packet')
    def test_send_ip_packet_contents_outgoing(self, mock_send_ip_packet):
        config = {'rule' : deny_tcp_basic_rules}
        f = Firewall(config, iface_int=EthernetInterface(), iface_ext=None)
        binary_packet = BinaryPacket().get_tcp_packet()
        f.handle_packet(PKT_DIR_OUTGOING, binary_packet)
        # Get the args
        args = mock_send_ip_packet.call_args
        pkt = args[0][0]
        outgoing_packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=pkt, geoDB=None)
        sent_packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        # Should be TCP
        self.assertEqual(socket.IPPROTO_TCP, outgoing_packet.get_protocol())
        # RST Flag should be 1
        self.assertTrue(outgoing_packet.get_rst_flag())
        # Destination should be the source of the packet we sent in
        self.assertEqual(outgoing_packet.get_dst_port(), sent_packet.get_src_port())
        self.assertEqual(outgoing_packet.get_dst_ip(), sent_packet.get_src_ip())


class BinaryPacketTests(unittest.TestCase):

    def test_ip_checksum(self):
        binary_packet = BinaryPacket()
        binary_packet.ip_proto = socket.IPPROTO_TCP
        ip_header = binary_packet.get_ip_header()
        # verify checksum
        self.assertEqual(0, checksum(ip_header))

    def test_tcp_checksum(self):
        binary_packet = BinaryPacket()
        tcp_packet = binary_packet.get_tcp_packet()
        # verify checksum
        self.assertEqual(0, checksum(tcp_packet))