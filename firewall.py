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
        self.country_code = None
        self.src_port = None
        self.qdcount = None
        self.qname = None
        self.qtype = None
        self.qclass = None

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

    def get_src_ip(self):
        if not self.src_ip:
            if self.pkt_dir == PKT_DIR_INCOMING:
                src_ip = self.pkt[12:16]
            else:
                src_ip = self.pkt[16:20]
            self.src_ip = socket.inet_ntoa(src_ip)
        return self.src_ip

    def get_country_code(self):
        if not self.country_code:
            self.country_code = self.geoDB.country_code(self.get_src_ip()).lower()
        return self.country_code

    def get_src_port(self):
        if not self.src_port:
            protocol = self.get_protocol()
            if protocol == socket.IPPROTO_TCP or protocol == socket.IPPROTO_UDP:
                if self.pkt_dir == PKT_DIR_INCOMING:
                    self.src_port = struct.unpack('!H', self.pkt[self.get_ip_end_byte():self.get_ip_end_byte() + 2])[0]
                else:
                    self.src_port = struct.unpack('!H', self.pkt[self.get_ip_end_byte() + 2:self.get_ip_end_byte() + 4])[0]

            elif protocol == socket.IPPROTO_ICMP:
                self.src_port = struct.unpack('!B', self.pkt[self.get_ip_end_byte():self.get_ip_end_byte() + 1])[0]
            else:
                self.src_port = None # Error?!
        return self.src_port

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

    def get_qtype(self):
        if not self.qtype:
            name = self.get_qname()
        return self.qtype

    def get_qclass(self):
        if not self.qclass:
            name = self.get_qname()
        return self.qclass

"""
Rules
"""

NOT_DEFINED = 'ndef'

RULE_TYPE_PIP = 'RULE_TYPE_PIP'
RULE_TYPE_DNS = 'RULE_TYPE_DNS'

RULE_PROTOCOL_DNS = 'dns'
RULE_ANY = 'any'

RULE_VERDICT = 0
RULE_PROTOCOL = 1
RULE_EXTERNAL_IP = 2
RULE_EXTERNAL_PORT = 3
RULE_DOMAIN_NAME = 2

RULE_RESULT_PASS = 'pass'
RULE_RESULT_DROP = 'drop'

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
            src_ip = packet.get_src_ip()

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
            src_port = packet.get_src_port()
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
        if packet.get_src_port() != 53:
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
