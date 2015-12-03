#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        rule_filename = config['rule']
        self.rules = Rules(filename=rule_filename)

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        geoipdb_filename = 'geoipdb.txt'
        self.geoDB = GeoIPDB(filename=geoipdb_filename)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        packet = Packet(pkt_dir, pkt, self.geoDB)
        result = self.rules.result_for_pkt(packet)
        if result == RULE_RESULT_PASS:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
        elif result == RULE_RESULT_DROP:
            # Drop!
            return
        elif result == RULE_RESULT_DENY:
            if packet.protocol == socket.IPPROTO_TCP:
                self.inject_rst_pkt(packet)
            elif packet.protocol == socket.IPPROTO_UDP:
                # Definitely a DNS since we only have deny for dns and tcp, not udp
                self.inject_dns_pkt(packet)


    def inject_rst_pkt(self, packet):
        binary_packet = BinaryPacket()
        # Set the reset flag
        binary_packet.tcp_rst = 1

        # Flip the directions
        binary_packet.tcp_dest = packet.get_src_port()
        binary_packet.dest_ip = packet.get_src_ip()
        binary_packet.tcp_source = packet.get_dst_port()
        binary_packet.source_ip = packet.get_dst_ip()

        # Generate the packet
        pkt = binary_packet.get_tcp_packet()
        # Send the rst
        if packet.pkt_dir == PKT_DIR_INCOMING:
            self.iface_ext.send_ip_packet(pkt)
        elif packet.pkt_dir == PKT_DIR_OUTGOING:
            self.iface_int.send_ip_packet(pkt)

    def inject_dns_pkt(self, packet):
        qtype = packet.get_qtype()
        if qtype == 28:
            # Do not send a response to qtype AAAA
            return
        # Construct a DNS response
        binary_packet = BinaryPacket()

        # Flip the directions
        binary_packet.udp_dest = packet.get_src_port()
        binary_packet.dest_ip = packet.get_src_ip()
        binary_packet.udp_source = packet.get_dst_port()
        binary_packet.source_ip = packet.get_dst_ip()

        # Get the qtype, question and qclass from the packet we received
        binary_packet.dns_qtype = packet.get_qtype()
        binary_packet.dns_question = packet.get_qname()
        binary_packet.dns_qclass = packet.get_qclass()
        binary_packet.dns_id = packet.get_dnsid()
        # Set the answer to the cat redirection
        binary_packet.dns_answer = CAT_REDIRECT_IP_ADDRESS
        binary_packet.dns_ttl = 60
        # Construct the dns answer
        dns_packet = binary_packet.get_dns_answer_packet()

        # Forward it to our internal interface
        if packet.pkt_dir == PKT_DIR_INCOMING:
            self.iface_ext.send_ip_packet(dns_packet)
        elif packet.pkt_dir == PKT_DIR_OUTGOING:
            self.iface_int.send_ip_packet(dns_packet)


"""
Misc helper functions
"""
def compareIP(ip1, ip2):
    """
    Return 0 if ip1 == ip2
    Return -1 if ip1 < ip2
    Return +1 if ip1 > ip2
    """
    ip1_comps = [int(comp) for comp in ip1.split(".")]
    ip2_comps = [int(comp) for comp in ip2.split(".")]
    components = [0, 1, 2, 3]
    for component in components:
        if ip1_comps[component] != ip2_comps[component]:
            if ip1_comps[component] < ip2_comps[component]:
                return -1
            else:
                return 1
    return 0

def ip_prefix_to_range(ip_prefix):
    ip_prefix_comps = ip_prefix.split("/")
    ip = ip_prefix_comps[0]
    packedIP = socket.inet_aton(ip)
    long_ip = struct.unpack("!L", packedIP)[0]

    mask = int(ip_prefix_comps[1])
    netmask = 2**32 - 1 - (2**(32 - mask) - 1)

    long_min_ip = (long_ip & netmask)
    long_max_ip = long_min_ip + 2**(32 - mask) - 1

    min_ip = socket.inet_ntoa(struct.pack("!L", long_min_ip))
    max_ip = socket.inet_ntoa(struct.pack("!L", long_max_ip))

    return (min_ip, max_ip)

"""
Importing from file
"""

class LineImporter(object):
    def import_filename(self, filename):
        with open(filename) as f:
            lines = f.readlines()
            # Get rid of newlines
            lines = [line.strip('\n') for line in lines]
            # Get rid of extra spaces
            lines = [' '.join(line.split()) for line in lines]
            # Store this
            self.lines = lines

"""
Rules
"""

NOT_DEFINED = 'ndef'

RULE_TYPE_PIP = 'RULE_TYPE_PIP'
RULE_TYPE_DNS = 'RULE_TYPE_DNS'
RULE_TYPE_HTTP = 'RULE_TYPE_HTTP'

RULE_PROTOCOL_DNS = 'dns'
RULE_PROTOCOL_HTTP = 'http'
RULE_ANY = 'any'

RULE_VERDICT = 0
RULE_PROTOCOL = 1
RULE_EXTERNAL_IP = 2
RULE_EXTERNAL_PORT = 3
RULE_DOMAIN_NAME = 2

RULE_RESULT_PASS = 'pass'
RULE_RESULT_DROP = 'drop'
RULE_RESULT_DENY = 'deny'
RULE_RESULT_LOG  = 'log'

class Rule:
    def __init__(self, rule_line):
        # To get rid of multiple white spaces
        rule_line = ' '.join(rule_line.split())
        rule_comps = rule_line.split(" ")
        # Get the verdict
        self.verdict = rule_comps[RULE_VERDICT]
        # Get the protocol
        self.protocol = rule_comps[RULE_PROTOCOL].lower()

        # Handle differently for dns / pip
        if self.protocol == RULE_PROTOCOL_DNS:
            self.type = RULE_TYPE_DNS
            self.domain_name = rule_comps[RULE_DOMAIN_NAME]
        elif self.protocol == RULE_PROTOCOL_HTTP:
            self.type = RULE_TYPE_HTTP
            self.domain_name = rule_comps[RULE_DOMAIN_NAME]
        else:
            self.type = RULE_TYPE_PIP
            self.external_ip = rule_comps[RULE_EXTERNAL_IP].lower()
            self.external_port = rule_comps[RULE_EXTERNAL_PORT]


    def rule_applies(self, packet):
        """
        Returns True if this rule applies to packet pkt,
        False if it does not
        """
        if self.type == RULE_TYPE_PIP:
            return self.rule_applies_pip(packet)
        elif self.type == RULE_TYPE_HTTP:
            return self.rule_applies_http(packet)
        else:
            return self.rule_applies_dns(packet)

    def rule_applies_pip(self, packet):
        """
        Handles checking if this rule applies to the packet
        for a PIP rule.
        """
        # If the protocol does not match, the rule does not apply
        if packet.get_protocol_string() != self.protocol:
            return False

        # If the external ip is any, don't do this check
        if self.external_ip != RULE_ANY:
            src_ip = packet.get_external_ip()

            # We are specified by a 2-byte country code
            if len(self.external_ip) == 2:
                country_code = packet.get_country_code()
                if country_code == GEOIPDB_CODE_NOT_FOUND or country_code != self.external_ip:
                    return False
            # We are specified by a prefix
            elif '/' in self.external_ip:
                ip_range = ip_prefix_to_range(self.external_ip)
                min_ip = ip_range[0]
                max_ip = ip_range[1]
                if compareIP(src_ip, min_ip) == -1:
                    # Less than the minimum IP in this range
                    return False
                if compareIP(src_ip, max_ip) == 1:
                    # More than the maximum IP in this range
                    return False
            # We are specified by an IP Address
            else:
                if src_ip != self.external_ip:
                    return False

        # If the external port is any, don't do this check
        if self.external_port != RULE_ANY:
            src_port = packet.get_external_port()
            if '-' in self.external_port:
                # Looking at a range
                port_comps = self.external_port.split("-")
                min_port = int(port_comps[0])
                max_port = int(port_comps[1])
                if src_port < min_port or src_port > max_port:
                    return False
            else:
                # Looking at a single value
                if src_port != int(self.external_port):
                    return False

        return True 

    def rule_applies_dns(self, packet):
        """
        Handles checking if this rule applies to the packet
        for a DNS rule.
        """
        # DNS rule only applies to udp packets
        if packet.get_protocol() != socket.IPPROTO_UDP:
            return False

        # DNS rule only applies to packets with port 53
        if packet.get_external_port() != 53:
            return False
        # Must have exactly 1 DNS query
        if packet.get_qdcount() > 1:
            return False

        qname = packet.get_qname()
        qtype = packet.get_qtype()
        qclass = packet.get_qclass()

        # Must have qtype 1 or 28
        if qtype != 1 and qtype != 28:
            return False

        # Must have qclass 1
        if qclass != 1:
            return False

        # Now check to make sure we aren't matching
        rule_components = [component.lower() for component in self.domain_name.split(".")]
        question_components = [component.lower() for component in qname.split(".")]

        # Left pad the components
        missing_rule_length = 3 - len(rule_components)
        missing_question_length = 3 - len(question_components)

        for _ in range(missing_rule_length):
            rule_components = ['!'] + rule_components
        for _ in range(missing_question_length):
            question_components = ['!'] + question_components

        # Now that they are both the same size, look from the right to the left
        for idx in range(3)[::-1]:
            if rule_components[idx] == '*':
                if question_components[idx] == '!':
                    return False
                else:
                    return True # Matches anything
            else:
                if rule_components[idx] != question_components[idx]:
                    return False # Does not match]

        return True

    def rule_applies_http(self, packet):
        # Http rule only applies to tcp packets
        if packet.get_protocol() != socket.IPPROTO_TCP:
            return False
        # Http rule only applies to packets with port 80
        if packet.get_external_port() != 80:
            return False
        return True


class Rules(LineImporter):

    def __init__(self, filename=None):
        self.rules = []
        # Call the import function
        super(Rules, self).import_filename(filename)
        # Convert these line strings to a list of rules
        for line in self.lines:
            # Ignore empty lines
            if len(line) == 0:
                continue
            # Ignore comment lines
            if line[0] == '%':
                continue
            # Create the rule
            rule = Rule(rule_line=line)
            self.rules.append(rule)
        # Invert the list, since the last rules hold priority
        self.rules = self.rules[::-1]

    def result_for_pkt(self, packet):
        # Get the protocol
        protocol = packet.get_protocol()
        if not protocol:
            # Something went wrong, drop the packet
            return RULE_RESULT_DROP
        
        # Check if any rule applies
        for rule in self.rules:
            # Return the verdict of the first rule that applies
            if rule.rule_applies(packet):
                return rule.verdict

        # If no rules apply, return PASS
        return RULE_RESULT_PASS


"""
GeoIPDB
"""

GEOIPDB_STARTING_IP = 0
GEOIPDB_ENDING_IP = 1
GEOIPDB_COUNTRY_CODE = 2
GEOIPDB_CODE_NOT_FOUND = 'GEOIPDB_CODE_NOT_FOUND'

class GeoIPDB(LineImporter):

    def __init__(self, filename):
        # We will store the DB file using a list and dictionary
        self.list = []
        self.hash = {}

        # Call the import function
        super(GeoIPDB, self).import_filename(filename)
        # Convert these line strings to list and dictionary
        for line in self.lines:
            line_tuple = line.split(" ")
            self.list.append(line_tuple)
            country_code = line_tuple[GEOIPDB_COUNTRY_CODE]
            if country_code not in self.hash:
                self.hash[country_code] = []
            # Append lines
            self.hash[country_code].append(line_tuple)

    def country_code(self, target_ip):
        """
        Returns the country code of the target ip
        or GEOIPDB_CODE_NOT_FOUND if it is not contained in our database
        """
        if len(self.list) > 0:
            return self.binary_search_country_code(target_ip, 0, len(self.list) - 1)
        else:
            return GEOIPDB_CODE_NOT_FOUND

    def binary_search_country_code(self, target_ip, start, end):
        difference = end - start
        if difference < 0:
            # Out of order
            return GEOIPDB_CODE_NOT_FOUND

        center = difference/2 + start
        # Get the center ip addresses
        center_line = self.list[center]
        center_start_ip = center_line[GEOIPDB_STARTING_IP]
        center_end_ip = center_line[GEOIPDB_ENDING_IP]
        # Get the comparisons
        start_comp = compareIP(target_ip, center_start_ip)
        end_comp = compareIP(target_ip, center_end_ip)

        # If it's either edge, or between both
        if (start_comp == 0 or end_comp == 0 or (start_comp == 1 and end_comp == -1)):
            # Found it
            return center_line[GEOIPDB_COUNTRY_CODE]
        else:
            if start_comp == -1:
                # Go left
                return self.binary_search_country_code(target_ip, start, center - 1)
            else:
                # Go right
                return self.binary_search_country_code(target_ip, center + 1, end)

"""
Packet
"""

class Packet:

    def __init__(self, pkt_dir, pkt, geoDB):
        self.pkt_dir = pkt_dir
        self.pkt = pkt
        self.geoDB = geoDB

        # Initialize variables that will be computed lazily
        self.protocol = None
        self.protocol_string = None
        self.src_ip = None
        self.dst_ip = None
        self.country_code = None
        self.src_port = None
        self.dst_port = None
        self.qdcount = None
        self.qname = None
        self.qtype = None
        self.qclass = None
        self.dnsid = None

        # Incase of ipoptions
        self.ip_end_byte = None # Default

    def protocol_number_to_string(self, protocol_number):
        if protocol_number == socket.IPPROTO_TCP:
            return 'tcp'
        if protocol_number == socket.IPPROTO_UDP:
            return 'udp'
        if protocol_number == socket.IPPROTO_ICMP:
            return 'icmp'
        return NOT_DEFINED

    def get_ip_end_byte(self):
        if not self.ip_end_byte:
            # Get the IHL
            version_ihl = struct.unpack('!B', self.pkt[0:1])[0]
            # Mask to get just the ihl
            ihl = version_ihl & 15
            self.ip_end_byte = ihl * 4
        return self.ip_end_byte

    def get_protocol(self):
        if not self.protocol:
            # Get the protocol
            protocol = struct.unpack('!B', self.pkt[9:10])
            if len(protocol) > 0:
                self.protocol = protocol[0]
            else:
                self.protocol = None
        return self.protocol

    def get_protocol_string(self):
        if not self.protocol_string:
            # Get the protocol string
            protocol_string = self.protocol_number_to_string(self.get_protocol())
            self.protocol_string = protocol_string
        return self.protocol_string

    def get_external_ip(self):
        if self.pkt_dir == PKT_DIR_INCOMING:
            return self.get_src_ip()
        else:
            return self.get_dst_ip()

    def get_src_ip(self):
        if not self.src_ip:
            src_ip = self.pkt[12:16]
            self.src_ip = socket.inet_ntoa(src_ip)
        return self.src_ip

    def get_dst_ip(self):
        if not self.dst_ip:
            src_ip = self.pkt[16:20]
            self.dst_ip = socket.inet_ntoa(src_ip)
        return self.dst_ip

    def get_rst_flag(self):
        flags = struct.unpack('!B', self.pkt[33:34])[0]
        return (flags & 4) == 4

    def get_country_code(self):
        if not self.country_code:
            self.country_code = self.geoDB.country_code(self.get_external_ip()).lower()
        return self.country_code

    def get_external_port(self):
        if self.pkt_dir == PKT_DIR_INCOMING:
            return self.get_src_port()
        else:
            return self.get_dst_port()

    def get_src_port(self):
        if not self.src_port:
            protocol = self.get_protocol()
            if protocol == socket.IPPROTO_TCP or protocol == socket.IPPROTO_UDP:
                self.src_port = struct.unpack('!H', self.pkt[self.get_ip_end_byte():self.get_ip_end_byte() + 2])[0]
            elif protocol == socket.IPPROTO_ICMP:
                self.src_port = struct.unpack('!B', self.pkt[self.get_ip_end_byte():self.get_ip_end_byte() + 1])[0]
            else:
                self.src_port = None # Error?!
        return self.src_port

    def get_dst_port(self):
        if not self.dst_port:
            protocol = self.get_protocol()
            if protocol == socket.IPPROTO_TCP or protocol == socket.IPPROTO_UDP:
                self.dst_port = struct.unpack('!H', self.pkt[self.get_ip_end_byte() + 2:self.get_ip_end_byte() + 4])[0]
            elif protocol == socket.IPPROTO_ICMP:
                self.dst_port = struct.unpack('!B', self.pkt[self.get_ip_end_byte():self.get_ip_end_byte() + 1])[0]
            else:
                self.dst_port = None # Error?!
        return self.dst_port

    def get_qdcount(self):
        if not self.qdcount:
            self.qdcount = struct.unpack('!H', self.pkt[self.get_ip_end_byte() + 12:self.get_ip_end_byte() + 14])[0]
        return self.qdcount

    def get_qname(self):
        if not self.qname:
            length_octet = struct.unpack('!B', self.pkt[self.get_ip_end_byte() + 20:self.get_ip_end_byte() + 21])[0]
            cursor = self.get_ip_end_byte() + 21
            string = ""
            while(length_octet != 0):
                string_builder = []
                while length_octet > 0:
                    char_byte = struct.unpack('!B', self.pkt[cursor:cursor+1])[0]
                    string_builder.append(chr(char_byte))
                    length_octet -= 1
                    cursor += 1
                if len(string) == 0:
                    string = "".join(string_builder)
                else:
                    string += "." + "".join(string_builder)
                length_octet = struct.unpack('!B', self.pkt[cursor:cursor+1])[0]
                cursor += 1

            self.qname = string

            # Now that we know the end of the qname area we can grab qtype and qclass
            self.qtype = struct.unpack('!H', self.pkt[cursor:cursor+2])[0]
            cursor += 2
            self.qclass = struct.unpack('!H', self.pkt[cursor:cursor+2])[0]

        return self.qname

    def get_dnsid(self):
        # First 2 bytes of dns header
        if not self.dnsid:
            self.dnsid = struct.unpack('!H', self.pkt[self.get_ip_end_byte() + 8:self.get_ip_end_byte() + 10])[0]
        return self.dnsid

    def get_qtype(self):
        if not self.qtype:
            name = self.get_qname()
        return self.qtype

    def get_qclass(self):
        if not self.qclass:
            name = self.get_qname()
        return self.qclass

CAT_REDIRECT_IP_ADDRESS = '169.229.49.130'

"""
Binary Packet from my test suite I made for project 3
will be useful in this project 4
"""
class BinaryPacket:
    """
    For testing

    Original code was based off of this site:
    http://www.binarytides.com/raw-socket-programming-in-python-linux/
    """
    def __init__(self):

        # THESE ARE ALL PLACEHOLDERS

        self.source_ip = '192.168.1.101'
        self.dest_ip = '192.168.1.1'
         
        # ip header fields
        self.ip_ihl = 5
        self.ip_ver = 4
        self.ip_tos = 0
        self.ip_tot_len = 0
        self.ip_id = 54321
        self.ip_frag_off = 0
        self.ip_ttl = 255
        self.ip_check = 0

        # tcp header fields
        self.tcp_source = 80
        self.tcp_dest = 80
        self.tcp_seq = 454
        self.tcp_ack_seq = 0
        self.tcp_doff = 5

        #tcp flags
        self.tcp_fin = 0
        self.tcp_syn = 1
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0
        self.tcp_window = socket.htons (5840)
        self.tcp_check = 0
        self.tcp_urg_ptr = 0

        # udp header fields
        self.udp_source = 1234
        self.udp_dest = 80
        self.udp_len = 0
        self.udp_check = 0

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

        self.dns_ttl = 1 # As according to the specification

        self.dns_question = "www.google.com"
        self.dns_answer = CAT_REDIRECT_IP_ADDRESS
        self.dns_qtype = 1
        self.dns_qclass = 1

    def checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            s = s + w
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        return s

    def get_ip_header(self, data_length = 0):
        self.ip_saddr = socket.inet_aton (self.source_ip)
        self.ip_daddr = socket.inet_aton (self.dest_ip)
        self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl
        self.ip_tot_len = 20 + data_length
        ip_header = struct.pack('!BBHHHBBH4s4s' , self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id,
            self.ip_frag_off, self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)
        # Figure out the ip_header checksum
        self.ip_check = self.checksum(ip_header)
        # Recalculate the ip_header
        ip_header = self.get_ip_header_with_correct_checksum()
        return ip_header

    def get_ip_header_with_correct_checksum(self):
        self.ip_saddr = socket.inet_aton (self.source_ip)
        self.ip_daddr = socket.inet_aton (self.dest_ip)
        self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl
        return struct.pack('!BBHHHBB' , self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id,
            self.ip_frag_off, self.ip_ttl, self.ip_proto) + struct.pack('H', self.ip_check) + struct.pack('!4s', self.ip_saddr) + struct.pack('!4s', self.ip_daddr)

    def get_icmp_header(self):
        return struct.pack('!BBHL', self.icmp_type, self.icmp_code, self.icmp_checksum, self.icmp_other)

    def get_tcp_header(self):
        tcp_offset_res = (self.tcp_doff << 4) + 0
        tcp_flags = self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + (self.tcp_psh <<3) \
            + (self.tcp_ack << 4) + (self.tcp_urg << 5)
        return struct.pack('!HHLLBBHHH' , self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, 
            tcp_offset_res, tcp_flags,  self.tcp_window, self.tcp_check, self.tcp_urg_ptr)

    def get_tcp_header_with_correct_checksum(self):
        tcp_offset_res = (self.tcp_doff << 4) + 0
        tcp_flags = self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + (self.tcp_psh <<3) \
            + (self.tcp_ack << 4) + (self.tcp_urg << 5)
        return struct.pack('!HHLLBBH' , self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, 
            tcp_offset_res, tcp_flags,  self.tcp_window) + struct.pack('H' , self.tcp_check) + struct.pack('!H' , self.tcp_urg_ptr)

    # Construct the packets
    def get_tcp_packet(self):
        # Set the protocol
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_check = 0
        # Generate the headers
        tcp_header = self.get_tcp_header()
        ip_header = self.get_ip_header(data_length=len(tcp_header))

        # Calculate and update the checksum for tcp
        
        # pseudo header fields
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , len(tcp_header))
        psh = psh + tcp_header
        self.tcp_check = self.checksum(psh)

        # Make the tcp header again
        tcp_header = self.get_tcp_header_with_correct_checksum()

        # Reset the checksums
        self.ip_check = 0
        self.tcp_check = 0
        return ip_header + tcp_header

    def get_udp_header(self):
        return struct.pack('!HHHH', self.udp_source, self.udp_dest, self.udp_len, 0)

    def get_udp_header_with_correct_checksum(self):
        return struct.pack('!HHH', self.udp_source, self.udp_dest, self.udp_len) + struct.pack('H', self.udp_check)

    def get_udp_packet(self, data = ""):
        self.ip_proto = socket.IPPROTO_UDP
        self.ip_check = 0
        # Set the length
        self.udp_len = 8 + len(data)

        # Generate the headers
        ip_header = self.get_ip_header(data_length=self.udp_len)
        udp_header = self.get_udp_header()

        # Calculate and update the checksum
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP
        psh = struct.pack('!4s4sBBH' , source_address, dest_address, placeholder, protocol, len(udp_header) + len(data))
        psh = psh + udp_header + data
        self.udp_check = self.checksum(psh)

        # Make the udp header again
        udp_header = self.get_udp_header_with_correct_checksum()

        return ip_header + udp_header

    def get_icmp_packet(self):
        self.ip_proto = socket.IPPROTO_ICMP
        return self.get_ip_header() + self.get_icmp_header()

    def get_dns_header(self):
        return struct.pack('!HBBHHHH', self.dns_id, self.dns_lflags, self.dns_rflags, self.dns_qdcount, self.dns_ancount, self.dns_nscount, self.dns_arcount)

    def get_dns_question(self):
        # Construct the qname from the components
        dns_comps = self.dns_question.split(".")
        qname = ""
        for component in dns_comps:
            length = len(component)
            qname += struct.pack('!B', length)
            for char in component:
                qname += struct.pack('!B', ord(char))
        qname += struct.pack('!B', 0)
        # Get the qtype
        qtype = struct.pack('!H', self.dns_qtype)
        # Get the qclass
        qclass = struct.pack('!H', self.dns_qclass)

        return qname + qtype + qclass

    def get_dns_answer(self):
        """
        For the dns answer I'm going to hijack the dns question
        creator I created when testing project 3
        """
        # Construct the qname from the components
        dns_comps = self.dns_question.split(".")
        name = ""
        for component in dns_comps:
            length = len(component)
            name += struct.pack('!B', length)
            for char in component:
                name += struct.pack('!B', ord(char))
        name += struct.pack('!B', 0)
        # Add the type
        _type = struct.pack('!H', self.dns_qtype)
        # Get the class
        _class = struct.pack('!H', self.dns_qclass)
        # Get the ttl
        ttl = struct.pack('!I', self.dns_ttl)
        # Make the rdata using the ip
        rdata = socket.inet_aton(self.dns_answer)
        rdlength = struct.pack('!H', len(rdata))

        return name + _type + _class + ttl + rdlength + rdata

    def get_dns_packet(self):
        self.ip_proto = socket.IPPROTO_UDP
        return self.get_udp_packet() + self.get_dns_header() + self.get_dns_question()

    def get_dns_answer_packet(self):
        self.ip_proto = socket.IPPROTO_UDP
        self.dns_ancount = 1
        self.dns_lflags = 128
        self.dns_rflags = 0
        dns_data = self.get_dns_header() + self.get_dns_question() + self.get_dns_answer()
        return self.get_udp_packet(data=dns_data) + dns_data
