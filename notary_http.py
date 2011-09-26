#   This file is part of the Perspectives Notary Server
#
#   Copyright (C) 2011 Dan Wendlandt
#   Copyright (C) 2011 Ondrej Mikle, CZ.NIC Labs
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
from xml.dom.minidom import getDOMImplementation
import struct
import base64
import hashlib
from M2Crypto import BIO, RSA
import sys
import threading 
from ssl_scan_sock import attempt_observation_for_service
import notary_common
import logging
import Queue

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

	def get_xml(self, service_id):
		"""Return xml with certificates' fingerprints.
		@param service_id: requested service
		@type service_id: notary_common.ObservedServer
		"""
		logger.info("Request for '%s'" % service_id)
		
		cur = db.Db.cursor()
		sql = """SELECT certificate, start_ts, end_ts FROM observations_view
			WHERE host = %s AND port = %s
			"""
		sql_data = (service_id.host, service_id.port)
		cur.execute(sql, sql_data)
		rows = cur.fetchall()
		db.Db.commit()
		
		timestamps_by_key = {}
		keys = []

		for row in rows:
			cert = str(row['certificate'])
			md5_fp = hashlib.md5(cert).digest()
			
			k = md5_fp
			if k not in timestamps_by_key:
				timestamps_by_key[k] = []
				keys.append(k)
			timestamps_by_key[k].append((row['start_ts'],row['end_ts']))
		
		if len(rows) == 0:
			try:
				on_demand_queue.put_nowait(service_id)
				logger.debug("on demand probe for '%s'" % service_id)
			except Queue.Full:
				logger.debug("On-demand queue full, not probing '%s'" % service_id)
			# return 404, assume client will re-query
			raise cherrypy.HTTPError(404)
	
		dom_impl = getDOMImplementation() 
		new_doc = dom_impl.createDocument(None, "notary_reply", None) 
		top_element = new_doc.documentElement
		top_element.setAttribute("version", "1") 
		top_element.setAttribute("sig_type", "rsa-md5") 
	
		## Packed data format:
		#service-id (variable length, terminated with null-byte) 
		#num_timespans (2-bytes)
		#key_len_bytes (2-bytes, 16 for version 1 - md5 only)
		#key type (1-byte), always has a value of 3 for SSL 
		#key (md5) data (length specified in key_len_bytes)
		#list of timespan start,end pairs  (length is 2 * 4 * num_timespans)
		packed_data = ""
	
		for k in keys:
			md5_fp = k
			key_elem = new_doc.createElement("key")
			key_elem.setAttribute("type","ssl")
			
			#binary fingerprints are packed in alphabetical order (md5, sha1, ...)
			fp_len = len(md5_fp)
			fp_bytes = md5_fp
			
			key_elem.setAttribute("fp", self._unpack_hex_with_colons(md5_fp))
			
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
	
		packed_data = service_id.old_str() + struct.pack("B", 0) + packed_data 
	
		m = hashlib.md5()
		m.update(packed_data)
		bio = BIO.MemoryBuffer(self.notary_priv_key)
		rsa_priv = RSA.load_key_bio(bio)
		sig_before_raw = rsa_priv.sign(m.digest(),'md5') 
		sig = base64.standard_b64encode(sig_before_raw) 
	
		top_element.setAttribute("sig",sig)
		return top_element.toprettyxml() 

	def index(self, host=None, port=None, service_type=None):
		"""
		Return signed XML response for given host, port and service.
		
		@param host: hostname
		@param port: port where service runs
		@param service_type: 1 (ssh) or 2 (ssl), although type 1 is obsolete
		"""
		if (host == None or port == None or service_type == None): 
			raise cherrypy.HTTPError(400)
		if service_type != "2":
			#we server only SSL, SSH is obsolete
			raise cherrypy.HTTPError(404)
		cherrypy.response.headers['Content-Type'] = 'text/xml'
		observed = notary_common.ObservedServer(str(host + ":" + port))
		
		return self.get_xml(observed)

	index.exposed = True


class OnDemandScanThread(threading.Thread):
	"""On-demand scanner for unknown services."""

	def __init__(self, timeout_sec, source_queue, result_queue):
		"""Initialize with source queue to read from and result queue
		to put results in.
		
		@param timeout_sec: timeout for scan
		@param source_queue: Queue.Queue object storing ObservedServer
		objects
		@param result_queue: Queue.Queue object where tuples of
		(notary_common.ObservedServer, notary_common.Observation) will
		be put as result of scan
		"""
		self.timeout_sec = timeout_sec
		self.source_queue = source_queue
		self.result_queue = result_queue
		threading.Thread.__init__(self)

	def run(self):
		while True:
			sid = self.source_queue.get()
			
			try: 
				fp = attempt_observation_for_service(sid, self.timeout_sec)
				self.result_queue.put((sid,fp))
			except Exception, e:
				logger.info("Failed to scan %s: %s" % (sid, e))
				
			self.source_queue.task_done()




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
notary_common.set_logger(logger)

#Queue for on-demand requests for new services
on_demand_queue = Queue.Queue(maxsize=50)
result_queue = Queue.Queue(maxsize=1000)

#Storage thread for putting on-demand scan results into DB
storage_thread = notary_common.StorageThread(result_queue)
storage_thread.setDaemon(True)
storage_thread.start()

#On-demand scan worker threads
for i in range(20):
	t = OnDemandScanThread(10, on_demand_queue, result_queue)
	t.setDaemon(True)
	t.start()


#Daemonizer(cherrypy.engine).subscribe()
cherrypy.quickstart(NotaryHTTPServer(config.Config), "/", config.Config.cherrypy_config)

