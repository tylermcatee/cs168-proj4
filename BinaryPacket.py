import socket, sys
from struct import *

class BinaryPacket:
    """
    For testing
    """
    def __init__(self):
        # DEFAULTS -- CAN BE CONFIGURED LATER

        self.source_ip = '192.168.1.101'
        self.dest_ip = '192.168.1.1'
         
        # ip header fields
        self.ip_ihl = 5 # For options!
        self.ip_ver = 4
        self.ip_tos = 0
        self.ip_tot_len = 0  # kernel will fill the correct total length
        self.ip_id = 54321   #Id of this packet
        self.ip_frag_off = 0
        self.ip_ttl = 255
        self.ip_check = 0    # kernel will fill the correct checksum

        # tcp header fields
        self.tcp_source = 1234   # source port
        self.tcp_dest = 80   # destination port
        self.tcp_seq = 454
        self.tcp_ack_seq = 0
        self.tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        self.tcp_fin = 0
        self.tcp_syn = 1
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0
        self.tcp_window = socket.htons (5840)    #   maximum allowed window size
        self.tcp_check = 0 # Doesn't matter for this project
        self.tcp_urg_ptr = 0

        # udp header fields
        self.udp_source = 1234
        self.udp_dest = 80
        self.udp_len = 0
        self.udp_check = 0 # Doesn't matter for this project

        # icmp header fields
        self.icmp_type = 0
        self.icmp_code = 0
        self.icmp_checksum = 0
        self.icmp_other = 0

        # dns header fields
        self.dns_id = 0 # (2 bytes)
        self.dns_lflags = 0 # qr, opcode, aa, tc, rd (1 byte)
        self.dns_rflags = 0 # ra, z, rcode (1 byte)
        self.dns_qdcount = 1 # (2 bytes)
        self.dns_ancount = 0 # (2 bytes)
        self.dns_nscount = 0 # (2 bytes)
        self.dns_arcount = 0 # (2 bytes)

        self.dns_question = "www.google.com"
        self.dns_qtype = 1
        self.dns_qclass = 1


    def get_ip_header(self):
        self.ip_saddr = socket.inet_aton ( self.source_ip )   #Spoof the source ip address if you want to
        self.ip_daddr = socket.inet_aton ( self.dest_ip )
        self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl
        return pack('!BBHHHBBH4s4s' , self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id,
            self.ip_frag_off, self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)

    def get_tcp_header(self):
        tcp_offset_res = (self.tcp_doff << 4) + 0
        tcp_flags = self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + (self.tcp_psh <<3) \
            + (self.tcp_ack << 4) + (self.tcp_urg << 5)
        return pack('!HHLLBBHHH' , self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, 
            tcp_offset_res, tcp_flags,  self.tcp_window, self.tcp_check, self.tcp_urg_ptr)

    def get_udp_header(self):
        return pack('!HHHH', self.udp_source, self.udp_dest, self.udp_len, self.udp_check)

    def get_icmp_header(self):
        return pack('!BBHL', self.icmp_type, self.icmp_code, self.icmp_checksum, self.icmp_other)

    def get_dns_header(self):
        return pack('!HBBHHHH', self.dns_id, self.dns_lflags, self.dns_rflags, self.dns_qdcount, self.dns_ancount, self.dns_nscount, self.dns_arcount)

    def get_dns_question(self):
        # Construct the qname from the components
        dns_comps = self.dns_question.split(".")
        qname = ""
        for component in dns_comps:
            length = len(component)
            qname += pack('!B', length)
            for char in component:
                qname += pack('!B', ord(char))
        qname += pack('!B', 0)
        # Get the qtype
        qtype = pack('!H', self.dns_qtype)
        # Get the qclass
        qclass = pack('!H', self.dns_qclass)

        return qname + qtype + qclass

    # Construct the packets
    def get_tcp_packet(self):
        self.ip_proto = socket.IPPROTO_TCP
        return self.get_ip_header() + self.get_tcp_header()
    def get_udp_packet(self):
        self.ip_proto = socket.IPPROTO_UDP
        return self.get_ip_header() + self.get_udp_header()
    def get_icmp_packet(self):
        self.ip_proto = socket.IPPROTO_ICMP
        return self.get_ip_header() + self.get_icmp_header()
    def get_dns_packet(self):
        self.ip_proto = socket.IPPROTO_UDP
        return self.get_ip_header() + self.get_udp_header() + self.get_dns_header() + self.get_dns_question()

