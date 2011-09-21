#   This file is part of the Perspectives Notary Server
#
#   Copyright (C) 2011 Dan Wendlandt
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, version 3 of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.


import socket
import struct 
import time
import binascii
import hashlib 
import traceback 
import sys
import errno 
import notary_common

import config
import db

# This is a lightweight version of SSL scanning that does not invoke openssl
# at all.  Instead, it executes the initial steps of the SSL handshake directly
# using a TCP socket and parses the data itself

SLEEP_LEN_SEC = 0.2

class SSLScanTimeoutException(Exception): 
	pass

class SSLAlertException(Exception): 
	
	def __init__(self,value): 
		self.value = value

def read_data(s,data_len, timeout_sec): 
	buf_str = ""
	start_time = time.time()
	while(True): 
		try:
			buf_str += s.recv(data_len - len(buf_str))
			if len(buf_str) == data_len:
				break
		except socket.error, e:
			if not is_nonblocking_exception(e): 
				raise e 
		if time.time() - start_time > timeout_sec: 
			raise SSLScanTimeoutException("timeout in read_data")
		time.sleep(SLEEP_LEN_SEC)
	return buf_str

def send_data(s, data, timeout_sec): 
	start_time = time.time() 
	while(True): 
		try:
			s.send(data)
			break 
		except socket.error, e: 
			if is_nonblocking_exception(e): 
				if time.time() - start_time > timeout_sec: 
					raise SSLScanTimeoutException("timeout in send_data")
				time.sleep(SLEEP_LEN_SEC)
			else: 
				raise e

def is_nonblocking_exception(e): 
	try: 
		return e.args[0] == errno.EAGAIN or \
		       e.args[0] == errno.EINPROGRESS or \
		       e.args[0] == errno.EALREADY 
	except: 
		return False
	
def do_connect(s, host, port, timeout_sec): 
	start_time = time.time() 
	while(True): 
		try:
			s.connect((host, port))
			break 
		except socket.error, e:
			if e.args[0] == errno.EISCONN: 
				break
			if is_nonblocking_exception(e):
				if time.time() - start_time > timeout_sec: 
					raise SSLScanTimeoutException("timeout in do_connect")
				time.sleep(SLEEP_LEN_SEC) 
			else: 
				raise e

def read_record(sock,timeout_sec): 
	rec_start = read_data(sock,5,timeout_sec)
	if len(rec_start) != 5: 
		raise Exception("Error: unable to read start of record")

	(rec_type, ssl_version, tls_version, rec_length) = struct.unpack('!BBBH',rec_start)
	rest_of_rec = read_data(sock,rec_length,timeout_sec)
	if len(rest_of_rec) != rec_length: 
		raise Exception("Error: unable to read full record")
	return (rec_type, rest_of_rec)

def get_all_handshake_protocols(rec_data):
	protos = [] 
	while len(rec_data) > 0: 
		t, b1,b2,b3 = struct.unpack('!BBBB',rec_data[0:4])
		l = (b1 << 16) | (b2 << 8) | b3
		protos.append((t, rec_data[4: 4 + l]))
		rec_data = rec_data[4 + l:]
	return protos 

# rfc 2246 says the server cert if the first one
# in the chain, so ignore everything else 
def get_server_cert_from_protocol(proto_data):
	"""Extract site certificate and return observed certificate.
	@param proto_data: server response (handshake from server hello)
	@return: notary_common.Observation object with cert and fingerprints
	"""
	proto_data = proto_data[3:] # get rid of 3-bytes describing length of all certs
	(b1,b2,b3) = struct.unpack("!BBB",proto_data[0:3])
	cert_len = (b1 << 16) | (b2 << 8) | b3
	cert = proto_data[3: 3 + cert_len]
	
	return notary_common.Observation([cert])

def attempt_observation_for_service(service_id, timeout_sec):
		"""Run observation for service
		@param service_id: requested service as notary_common.ObservedServer
		@param timeout_sec: scanning timeout
		@return: notary_common.Observation with cert and fingerprints of service
		@raise SSLScanTimeoutException: on timeout
		"""
		host, port = service_id.host, service_id.port
		# if we want to try SNI, do such a scan but if that
		# scan fails with an SSL alert, retry with a non SNI request
		if config.Config.use_sni and host[-1:].isalpha(): 
			try: 
				return run_scan(host, port, timeout_sec, True)
			except SSLAlertException: 
				pass

		return run_scan(host, port, timeout_sec, False) 
		
def run_scan(dns, port, timeout_sec, sni_query):
	"""Run SSL/TLS scan on given host.
	@param dns: hostname
	@param port: port
	@param timeout_sec: timeout in seconds
	@param sni_query: True iff Server Name Indication extension should be used,
		use only if hostname is specified via FQDN and not just IP
	@return: observation as instance of notary_common.Observation
	@raise SSLScanTimeoutException: on timeout
	"""
	try: 	
		if sni_query:
			# only do SNI query for DNS names, per RFC
			client_hello_hex = get_sni_client_hello(dns)
		else: 
			client_hello_hex = get_standard_client_hello()

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setblocking(0) 
		do_connect(sock, dns, int(port),timeout_sec)
		client_hello = binascii.a2b_hex(client_hello_hex)
		send_data(sock, client_hello,timeout_sec)
	
		fp = None
		start_time = time.time() 
		while not fp: 
			t,rec_data = read_record(sock,timeout_sec)
			if t == 22: # handshake message
				all_hs_protos = get_all_handshake_protocols(rec_data) 
				for p in all_hs_protos: 
					if p[0] == 11: 
						# server certificate message
						fp = get_server_cert_from_protocol(p[1])
						break
			elif t == 21: # alert message
				raise SSLAlertException(rec_data) 
	
			if not fp: 
				time.sleep(SLEEP_LEN_SEC)
				if time.time() - start_time > timeout_sec: 
					break
		try: 
			sock.shutdown(socket.SHUT_RDWR) 
		except: 
			pass
		if not fp: 
			raise SSLScanTimeoutException("timeout waiting for data")
		sock.close()
		return fp 

	# make sure we always close the socket, but still propogate the exception
	except Exception, e: 
		try: 
			sock.close()
		except: 
			pass
		raise e

def get_standard_client_hello():
	"""SSLv2 encoded client hello"""
	return "8077010301004e0000002000003900003800003500001600001300000a0700c000003300003200002f0300800000050000040100800000150000120000090600400000140000110000080000060400800000030200800000ff9c82ce1e4bc89df2c726b7cebe211ef80a611945d140834eede5674b597be487" 
	

def get_twobyte_hexstr(intval): 
	"""Return packed value of intval as hex string of two bytes, network order."""
	return binascii.b2a_hex(struct.pack("!H", intval))

def get_threebyte_hexstr(intval): 
	"""Return packed value of intval as hex string of three bytes, network order."""
	return binascii.b2a_hex(struct.pack("!I", intval)[1:])

def get_hostname_extension(hostname):
	"""SNI extension for TLSv1 client hello"""
	
	hex_hostname = binascii.b2a_hex(hostname)
	hn_len = len(hostname) 
	return "0000" + get_twobyte_hexstr(hn_len + 5) +  get_twobyte_hexstr(hn_len + 3) + \
				"00" + get_twobyte_hexstr(hn_len) + hex_hostname

def get_sni_client_hello(hostname):
	"""TLSv1 client hello with SNI extension"""
	hn_extension = get_hostname_extension(hostname)
	all_extensions = hn_extension 
	the_rest = "03014d786109055e4736b93b63c371507f824c2d0f05a25b2d54b6b52a1e43c2a52c00002800390038003500160013000a00330032002f000500040015001200090014001100080006000300ff020100" + get_twobyte_hexstr(len(all_extensions)/2) + all_extensions 
	proto_len = (len(the_rest) / 2)
	rec_len = proto_len + 4
	return "160301" + get_twobyte_hexstr(rec_len) + "01" + get_threebyte_hexstr(proto_len) + the_rest 

if __name__ == "__main__":


	if len(sys.argv) != 3:
		print >> sys.stderr, "ERROR: usage: <service-id> <config_file>"
		exit(1)

	config.config_initialize(sys.argv[2])
	db.db_initialize(config.Config)
	
	service_id = notary_common.ObservedServer(sys.argv[1])
	try:

		fp = attempt_observation_for_service(service_id, 10) 
	
		print "Successful scan complete: '%s' has key '%s' " % (service_id,fp)
		notary_common.report_observation(service_id, fp) 

	except:
		print "Error scanning for %s" % service_id 
		traceback.print_exc(file=sys.stdout)
		
