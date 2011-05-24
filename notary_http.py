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

import cherrypy
from xml.dom.minidom import parseString, getDOMImplementation
import struct
import base64
import hashlib
from M2Crypto import BIO, RSA, EVP
import sys
import threading 
from ssl_scan_sock import attempt_observation_for_service, SSLScanTimeoutException
import traceback 
import notary_common

import config
import db

class NotaryHTTPServer(object):

	def __init__(self, notary_config):
		"""@param notary_config: config.NotaryServerConfig instance - parsed config"""
		self.config = notary_config
		self.notary_priv_key = open(self.config.keyfile,'r').read() 
		self.active_threads = 0
		#lock for accessing self.active_threads 
		self.thread_lock = threading.Lock()
		
	def inc_active_threads(self):
		self.thread_lock.acquire()
		self.active_threads += 1
		self.thread_lock.release()

	def dec_active_threads(self):
		self.thread_lock.acquire()
		self.active_threads -= 1
		self.thread_lock.release()

	@staticmethod
	def _unpack_hex_with_colons(b):
		"""Unpacks binary string to hex representation with bytes delimited
		by colon, e.g. "11:22:33:44:de:ad:be:ef".
		"""
		fmt = ":".join(["%02X"]*len(b))
		return fmt % struct.unpack("%dB"%len(b), b)

	def get_xml(self, service_id):
		"""Return "old-style" xml with md5 certificates' fingerprints.
		@param service_id: requested service
		@type service_id: notary_common.ObservedServer
		"""
		print "Request for '%s'" % service_id
		sys.stdout.flush()
		
		cur = db.Db.cursor()
		sql = """SELECT md5, start_ts, end_ts FROM observations_view
			WHERE host = %s AND
				port = %s AND
				service_type = %s
			"""
		sql_data = (service_id.host, service_id.port, service_id.service_type)
		cur.execute(sql, sql_data)
		rows = cur.fetchall()
		db.Db.commit()
		
		timestamps_by_key = {}
		keys = set()

		#key "k" is md5 hash of certificate
		for row in rows:
			k = row['md5']
			if k not in keys: 
				timestamps_by_key[k] = []
				keys.add(k) 
			timestamps_by_key[k].append((row['start_ts'],row['end_ts']))
		
		if len(rows) == 0: 
			# rate-limit on-demand probes
			if self.active_threads < 10: 
				print "on demand probe for '%s'" % service_id  
				t = OnDemandScanThread(service_id,10,self)
				t.start()
			else: 
				print "Exceeded on demand threshold, not probing '%s'" % service_id  
			# return 404, assume client will re-query
			raise cherrypy.HTTPError(404)
	
		dom_impl = getDOMImplementation() 
		new_doc = dom_impl.createDocument(None, "notary_reply", None) 
		top_element = new_doc.documentElement
		top_element.setAttribute("version","1") 
		top_element.setAttribute("sig_type", "rsa-md5") 
	
		packed_data = ""
	
		for k in keys:
			key_elem = new_doc.createElement("key")
			key_elem.setAttribute("type","ssl")
			key_elem.setAttribute("fp", self._unpack_hex_with_colons(k))
			top_element.appendChild(key_elem)
			num_timespans = len(timestamps_by_key[k])
			#in the next struct.pack: 16 is length of md5 hash, 3 is "ssl"
			#service type, inferred from FF extension
			head = struct.pack("BBBBB", (num_timespans >> 8) & 255, num_timespans & 255, 0, 16,3)
			fp_bytes = str(k) #k is binary buffer()
			ts_bytes = ""
			for ts in sorted(timestamps_by_key[k], key=lambda t_pair: t_pair[0]):
				ts_start = ts[0]
				ts_end	= ts[1]
				ts_elem = new_doc.createElement("timestamp")
				ts_elem.setAttribute("end",str(ts_end))
				ts_elem.setAttribute("start", str(ts_start))
				key_elem.appendChild(ts_elem) 
				ts_bytes += struct.pack("BBBB", ts_start >> 24 & 255,
							ts_start >> 16 & 255,
							ts_start >> 8 & 255,
							ts_start & 255)
				ts_bytes += struct.pack("BBBB", ts_end >> 24 & 255,
							ts_end >> 16 & 255,
							ts_end >> 8 & 255,
							ts_end & 255)
			packed_data =(head + fp_bytes + ts_bytes) + packed_data   
	
		packed_data = str(service_id) + struct.pack("B", 0) + packed_data 
	
		m = hashlib.md5()
		m.update(packed_data)
		bio = BIO.MemoryBuffer(self.notary_priv_key)
		rsa_priv = RSA.load_key_bio(bio)
		sig_before_raw = rsa_priv.sign(m.digest(),'md5') 
		sig = base64.standard_b64encode(sig_before_raw) 
	
		top_element.setAttribute("sig",sig)
		return top_element.toprettyxml() 

	def index(self, host=None, port=None, service_type=None, version="1"):
		"""
		Return signed XML response for given host, port and service.
		
		@param host: hostname
		@param port: port where service runs
		@param service_type: 1 (ssh) or 2 (ssl), see notary_common.ObservedServer
		@param version: response version, current version is 1 (with md5 hash only),
			future versions will provide more hashes
		"""
		if (host == None or port == None or service_type == None): 
			raise cherrypy.HTTPError(400)
		cherrypy.response.headers['Content-Type'] = 'text/xml'
		observed = notary_common.ObservedServer(str(host + ":" + port + "," + service_type))
		
		#currently returns only version 1
		return self.get_xml(observed)

	index.exposed = True


class OnDemandScanThread(threading.Thread): 

	def __init__(self, sid,timeout_sec,server_obj):
		self.sid = sid
		self.server_obj = server_obj
		self.timeout_sec = timeout_sec
		threading.Thread.__init__(self)
		self.server_obj.inc_active_threads()

	def run(self): 
		try:
			fp = attempt_observation_for_service(self.sid, self.timeout_sec)
			notary_common.report_observation(self.sid, fp)
		except Exception, e:
			traceback.print_exc(file=sys.stdout)

		self.server_obj.dec_active_threads()




if len(sys.argv) != 2:
	print "usage: <notary-config-file>" 
	exit(1) 

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

cherrypy.config.update({ 'server.socket_port' : 8080,
			 'server.socket_host' : "0.0.0.0",
			 'request.show_tracebacks' : False,  
			 'log.access_file' : None,  # default for production 
			 'log.error_file' : 'error.log', 
			 'log.screen' : False } ) 
cherrypy.quickstart(NotaryHTTPServer(config.Config))

