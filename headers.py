# Shidhi Mohammad Bin Arif
# V00911512

import struct

class GlobalHeader:
	magic_number = None		 
	version_minor = None		 
	version_major = None		 
	thiszone = None
	sigfigs = None			 
	snaplen = None			 
	network = None			 

	def __init__(self, buffer):
		self.magic_number, self.version_minor, self.version_major, self.thiszone, self.sigfigs, self.snaplen, self.network = struct.unpack('IHHiIII', buffer)

class PacketHeader:
	ts_sec = None			 
	ts_usec = None			 
	incl_len = None			 
	orig_len = None			 

	def __init__(self):
		self.ts_sec = 0
		self.ts_usec = 0
		self.incl_len = 0
		self. orig_len = 0

	def set_header(self, buffer):
		self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack('IIII', buffer)

class IPV4Header:
	ihl = None			 
	total_length = None		 
	identification = None
	flags = None			 
	fragment_offset = None		 
	ttl = None			 
	protocol = None			 
	src_ip = None			 
	dst_ip = None			 

	def set_ihl(self, value):
		result = struct.unpack('B', value)[0]
		self.ihl = (result & 15) * 4

	def set_total_len(self, buffer):
		num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
		num2 = (buffer[0] & 15) * 16 * 16
		num3 = ((buffer[1] & 240) >> 4) * 16
		num4 = (buffer[1] & 15)
		self.total_length = num1 + num2 + num3 + num4
	
	def set_ip(self, buffer1, buffer2):
		src_addr = struct.unpack('BBBB', buffer1)
		dst_addr = struct.unpack('BBBB', buffer2)
		self.src_ip = str(src_addr[0]) + '.' + str(src_addr[1]) + '.' + str(src_addr[2]) + '.' + str(src_addr[3])
		self.dst_ip = str(dst_addr[0]) + '.' + str(dst_addr[1]) + '.' + str(dst_addr[2]) + '.' + str(dst_addr[3])

	def set_identification(self, buffer):
		result = struct.unpack('BB', buffer)
		self.identification = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_fragment_offset(self, buffer):
		num0 = hex(((buffer[0] & 224) >> 5))
		num1 = ((buffer[0] & 16) >> 4) * 16 * 16 * 16
		num2 = (buffer[0] & 15) * 16 * 16
		num3 = ((buffer[1] & 240) >> 4) * 16
		num4 = (buffer[1] & 15)
		self.flags = num0
		self.fragment_offset = (num1 + num2 + num3 + num4) * 8

	def set_ttl(self, buffer):
		self.ttl = struct.unpack('B', buffer)[0]

	def set_protocol(self, buffer):
		self.protocol = struct.unpack('B', buffer)[0]
		
class UDPHeader:
	src_port = None
	dst_port = None
	udp_length = None
	checksum = None

	def set_src_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.src_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_dst_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.dst_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_udp_len(self, buffer):
		result = struct.unpack('BB', buffer)
		self.udp_length = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_checksum(self, buffer):
		result = struct.unpack('BB', buffer)
		self.checksum = str(hex(result[0])) + str(hex(result[1]))
		
class ICMPHeader:
	type_num = None
	code = None
	src_port = None
	dst_port = None
	sequence = None

	def set_type(self, buffer):
		result = struct.unpack('B', buffer)[0]
		self.type_num = int(result)

	def set_code(self, buffer):
		result = struct.unpack('B', buffer)[0]
		self.code = int(result)

	def set_src_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.src_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_dst_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.dst_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_sequence(self, buffer):
		result = struct.unpack('BB', buffer)
		self.sequence = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

class Packet:
	header = None
	ipv4 = None	
	icmp = None			
	udp = None			
	data = None			
	payload = None			
	timestamp = None		

	def __init__(self):
		self.header = PacketHeader()
		self.ipv4 = IPV4Header()
		self.icmp = ICMPHeader()
		self.udp = UDPHeader()
		self.data = b''
		self.payload = 0
		self.timestamp = 0

	def set_header(self, buffer):
		self.header.set_header(buffer)

	def set_data(self, buffer):
		self.data = buffer

	def set_number(self, value):
		self.number = value

	def set_rtt(self, p):
		rtt = p.timestamp - self.timestamp
		self.RTT_value = round(rtt, 8)

	def set_timestamp(self, orig_time):
		seconds = self.header.ts_sec
		microseconds = self.header.ts_usec
		self.timestamp = 1000 * round(seconds + microseconds * 0.000000001 - orig_time, 6)

	def set_ipv4(self):
		offset = 14 # ethernet header length
		self.ipv4.set_ihl(self.data[offset+0: offset+1])
		self.ipv4.set_total_len(self.data[offset+2: offset+4])
		self.ipv4.set_identification(self.data[offset+4: offset+6])
		self.ipv4.set_fragment_offset(self.data[offset+6: offset+8])
		self.ipv4.set_ttl(self.data[offset+8: offset+9])
		self.ipv4.set_protocol(self.data[offset+9: offset+10])
		self.ipv4.set_ip(self.data[offset+12: offset+16], self.data[offset+16: offset+20])

	def set_icmp(self):
		offset = 14 + self.ipv4.ihl
		self.icmp.set_type(self.data[offset+0: offset+1])
		self.icmp.set_code(self.data[offset+1: offset+2])
		
		if self.icmp.type_num == 0 or self.icmp.type_num == 8:
			self.icmp.set_sequence(self.data[offset+6: offset+8])

		offset += 8 + self.ipv4.ihl
		if offset+4 <= self.header.incl_len:
			if self.icmp.type_num != 0 and self.icmp.type_num != 8:
				self.icmp.set_sequence(self.data[offset+6: offset+8]) # also windows
			self.icmp.set_src_port(self.data[offset+0: offset+2])
			self.icmp.set_dst_port(self.data[offset+2: offset+4])
		else:
			self.icmp.src_port = 0
			self.icmp.dst_port = 0		

	def set_udp(self):
		offset = 14 + self.ipv4.ihl
		self.udp.set_src_port(self.data[offset+0: offset+2])
		self.udp.set_dst_port(self.data[offset+2: offset+4])
		self.udp.set_udp_len(self.data[offset+4: offset+6])
		self.udp.set_checksum(self.data[offset+6: offset+8])