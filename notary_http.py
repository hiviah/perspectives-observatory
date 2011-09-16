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
from cherrypy.process.plugins import Daemonizer
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
import logging

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
		by colon in lowercase, e.g. "11:22:33:44:de:ad:be:ef".
		"""
		fmt = ":".join(["%02X"]*len(b))
		colonized_hexstr = fmt % struct.unpack("%dB"%len(b), b)
		return colonized_hexstr.lower()

	def get_xml(self, service_id, version=1):
		"""Return xml with certificates' fingerprints.
		@param service_id: requested service
		@type service_id: notary_common.ObservedServer
		@param version: 1 (for old md5-only) or 2 (multiple hashes, currently md5 and sha1)
		"""
		logger.info("Request for '%s'" % service_id)
		sys.stdout.flush()
		
		cur = db.Db.cursor()
		sql = """SELECT md5, sha1, start_ts, end_ts FROM observations_view
			WHERE host = %s AND
				port = %s AND
				service_type = %s
			"""
		sql_data = (service_id.host, service_id.port, service_id.service_type)
		cur.execute(sql, sql_data)
		rows = cur.fetchall()
		db.Db.commit()
		
		timestamps_by_key = {}
		keys = []

		for row in rows:
			md5_fp = str(row['md5']) #DB query returns MD5 and SHA1 as binary buffer()
			#hashes other than md5 might not be present in older DB records
			sha1_fp = row['sha1'] is not None and str(row['sha1']) or None
			
			k = (md5_fp, sha1_fp)
			if k not in timestamps_by_key:
				timestamps_by_key[k] = []
				keys.append(k)
			timestamps_by_key[k].append((row['start_ts'],row['end_ts']))
		
		if len(rows) == 0: 
			# rate-limit on-demand probes
			if self.active_threads < 10: 
				logger.debug("on demand probe for '%s'" % service_id)
				t = OnDemandScanThread(service_id,10,self)
				t.start()
			else: 
				logger.debug("Exceeded on demand threshold, not probing '%s'" % service_id)
			# return 404, assume client will re-query
			raise cherrypy.HTTPError(404)
	
		dom_impl = getDOMImplementation() 
		new_doc = dom_impl.createDocument(None, "notary_reply", None) 
		top_element = new_doc.documentElement
		top_element.setAttribute("version", str(version)) 
		top_element.setAttribute("sig_type", "rsa-md5") 
	
		## Packed data format:
		#service-id (variable length, terminated with null-byte) 
		#num_timespans (2-bytes)
		#key_len_bytes (2-bytes, 16 for version 1 - md5 only; version 2 has
		#	the length as sum of all various hashes, e.g. 16+20=36 for md5 and sha1
		#key type (1-byte), always has a value of 3 for SSL 
		#key data (length specified in key_len_bytes; fingerprints themselves are
		#	ordered alphabetically, i.e. bytes of md5, then bytes of sha1 hash)
		#list of timespan start,end pairs  (length is 2 * 4 * num_timespans)
		packed_data = ""
	
		for k in keys:
			(md5_fp, sha1_fp) = k
			key_elem = new_doc.createElement("key")
			key_elem.setAttribute("type","ssl")
			
			#binary fingerprints are packed in alphabetical order (md5, sha1, ...)
			fp_len = len(md5_fp)
			fp_bytes = md5_fp
			
			if version == 1:
				key_elem.setAttribute("fp", self._unpack_hex_with_colons(md5_fp))
			else:
				key_elem.setAttribute("md5", self._unpack_hex_with_colons(md5_fp))
				if sha1_fp is not None: #can be NULL in DB for compatibility reasons
					fp_len += len(sha1_fp)
					fp_bytes += sha1_fp
					key_elem.setAttribute("sha1", self._unpack_hex_with_colons(sha1_fp))
			
			top_element.appendChild(key_elem)
			num_timespans = len(timestamps_by_key[k])
			
			TYPE_SSL = 3 #from FF extension's comments
			head = struct.pack("!2HB", num_timespans, fp_len, TYPE_SSL)
			ts_bytes = ""
			for ts in sorted(timestamps_by_key[k], key=lambda t_pair: t_pair[0]):
				ts_start = ts[0]
				ts_end	= ts[1]
				ts_elem = new_doc.createElement("timestamp")
				ts_elem.setAttribute("end",str(ts_end))
				ts_elem.setAttribute("start", str(ts_start))
				key_elem.appendChild(ts_elem) 
				ts_bytes += struct.pack("!I", ts_start)
				ts_bytes += struct.pack("!I", ts_end)
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
		if (host == None or port == None or service_type == None or version not in ("1", "2")): 
			raise cherrypy.HTTPError(400)
		cherrypy.response.headers['Content-Type'] = 'text/xml'
		observed = notary_common.ObservedServer(str(host + ":" + port + "," + service_type))
		
		return self.get_xml(observed, int(version))

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
		finally:
			#return connection back to pool, otherwise it won't know it's
			#not used anymore
			db.Db.putconn()

		self.server_obj.dec_active_threads()




if len(sys.argv) != 2:
	print "usage: <notary-config-file>" 
	exit(1) 

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

# create custom logger to not interfere with cherrypy logging
logger = logging.getLogger('notary_http')
logger.setLevel(config.Config.app_loglevel)
logger.propagate = False
ch = logging.FileHandler(config.Config.app_log)
ch.setLevel(config.Config.app_loglevel)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
ch.setFormatter(formatter)
logger.addHandler(ch)

#Daemonizer(cherrypy.engine).subscribe()
cherrypy.quickstart(NotaryHTTPServer(config.Config), "/", config.Config.cherrypy_config)

