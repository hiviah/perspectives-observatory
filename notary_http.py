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

def create_logger(filename, loglevel):
	"""Create custom logger to not interfere with cherrypy logging, because
	it doesn't propagate to root logger.
	"""
	logger = logging.getLogger('notary_http')
	logger.setLevel(loglevel)
	logger.propagate = False
	ch = logging.FileHandler(filename)
	ch.setLevel(loglevel)
	formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
	ch.setFormatter(formatter)
	logger.addHandler(ch)
	
	return logger
	
def start_on_demand_threads(on_demand_queue, result_queue, scanned_set):
	"""Start on-demand scan thread(s) and storage thread(s).
	
	@param on_demand_queue: Queue.Queue storing notary_common.ObservedServer
	instances to scan.
	@param result_queue: Queue.Queue storing scanned results as tuple
	(notary_common.ObservedServer, notary_common.Observation)
	@param scanned_set: notary_common.ScannedSet storing service_ids to be
	scanned
	"""
	#Storage threads for putting on-demand scan results into DB
	for i in range(config.Config.on_demand_storage_threads):
		storage_thread = notary_common.StorageThread(result_queue, scanned_set)
		storage_thread.setDaemon(True)
		storage_thread.start()
	
	#On-demand scan worker threads
	for i in range(config.Config.on_demand_scan_threads):
		t = OnDemandScanThread(config.Config.on_demand_scan_timeout,
					on_demand_queue, result_queue, scanned_set)
		t.setDaemon(True)
		t.start()

class NotaryHTTPServer(object):
	"""Class serving HTTP requests passed onto by CherryPy."""

	def __init__(self, notary_config, on_demand_queue, scanned_set):
		"""
		@param notary_config: config.NotaryServerConfig instance - parsed config
		@param on_demand_queue: Queue.Queue where to put ObservedServer
		instances to scan
		@param scanned_set: notary_common.ScannedSet of instances waiting
		to be scanned and stored
		"""
		self.config = notary_config
		self.notary_priv_key = open(self.config.keyfile,'r').read()
		self.on_demand_queue = on_demand_queue
		self.scanned_set = scanned_set

	@staticmethod
	def _unpack_hex_with_colons(b):
		"""Unpacks binary string to hex representation with bytes delimited
		by colon in lowercase, e.g. "11:22:33:44:de:ad:be:ef".
		"""
		fmt = ":".join(["%02X"]*len(b))
		colonized_hexstr = fmt % struct.unpack("%dB"%len(b), b)
		return colonized_hexstr.lower()

	def sign_rsa_base64(self, data, digest):
		"""Sign hash of data with the server's private key.
		@param data: binary data blob
		@param digest: digest to use ('md5', 'sha1', 'sha256'...)
		@returns: base64-encoded signature of hashed data
		"""
		m = hashlib.new(digest)
		m.update(data)
		bio = BIO.MemoryBuffer(self.notary_priv_key)
		rsa_priv = RSA.load_key_bio(bio)
		signature = rsa_priv.sign(m.digest(), digest)
		base64_signature = base64.standard_b64encode(signature)
		
		return base64_signature
		
	def launch_on_demand_probe(self, service_id):
		"""Launches on-demand probe for service_id if not already
		scheduled.
		
		@param service_id. notary_common.ObservedServer to scan
		@returns: True if scan was launched or already scheduled,
			False if queue is full
		"""
		try:
			if self.scanned_set.insert(service_id):
				self.on_demand_queue.put_nowait(service_id)
				logger.debug("on demand probe for '%s'" % service_id)
			return True
		except Queue.Full:
			logger.debug("On-demand queue full, not probing '%s'" % service_id)
			self.scanned_set.remove(service_id)
			return False
			
	def get_xml(self, service_id):
		"""Return xml with certificates' fingerprints.
		@param service_id: requested service
		@type service_id: notary_common.ObservedServer
		"""
		logger.info("Request for '%s'" % service_id)
		
		ee_certs = notary_common.get_ee_certs(service_id)
		
		ee_certs_by_key = {}
		keys = []

		for ee_cert in ee_certs:
			md5_fp = hashlib.md5(ee_cert.cert).digest()
			
			k = md5_fp
			if k not in ee_certs_by_key:
				ee_certs_by_key[k] = []
				keys.append(k)
			ee_certs_by_key[k].append(ee_cert)
		
		#If we have no record of the service_id, launch a on-demand
		#scan, but only if the scan for the same service_id is not
		#already scheduled or being scanned.
		#Perspectives Firefox extensions likes to fire 3 requests
		#often faster than we get the scan results, so this way we won't
		#clog up the queue with unnecessary scans.
		if len(ee_certs) == 0:
			self.launch_on_demand_probe(service_id)
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
			
			fp_len = len(md5_fp)
			fp_bytes = md5_fp
			
			key_elem.setAttribute("fp", self._unpack_hex_with_colons(md5_fp))
			
			top_element.appendChild(key_elem)
			num_timespans = len(ee_certs_by_key[k])
			
			TYPE_SSL = 3 #from FF extension's comments
			head = struct.pack("!2HB", num_timespans, fp_len, TYPE_SSL)
			ts_bytes = ""
			for ee_cert in sorted(ee_certs_by_key[k], key=lambda ee_cert: ee_cert.start_ts):
				ts_start = ee_cert.start_ts
				ts_end	= ee_cert.end_ts
				ts_elem = new_doc.createElement("timestamp")
				ts_elem.setAttribute("end",str(ts_end))
				ts_elem.setAttribute("start", str(ts_start))
				key_elem.appendChild(ts_elem) 
				ts_bytes += struct.pack("!I", ts_start)
				ts_bytes += struct.pack("!I", ts_end)
			packed_data =(head + fp_bytes + ts_bytes) + packed_data   
	
		packed_data = service_id.old_str() + struct.pack("B", 0) + packed_data 
	
		sig = self.sign_rsa_base64(packed_data, digest="md5")
		top_element.setAttribute("sig",sig)
		return top_element.toprettyxml() 

	@cherrypy.expose
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

	@cherrypy.expose
	def get_certs(self, host=None, port=None, **kwargs):
		"""Returns XML response containing certificate data and their
		timestamps. Only leaf (EE) certificates are included, not the
		whole chain.
		
		@param host: hostname
		@param port: port where service runs
		"""
		if (host is None or port is None):
			raise cherrypy.HTTPError(400)
		host_port = str(host + ":" + port)
		service_id = notary_common.ObservedServer(host_port)
		ee_certs = notary_common.get_ee_certs(service_id)
		
		if len(ee_certs) == 0:
			self.launch_on_demand_probe(service_id)
			raise cherrypy.HTTPError(404)
		
		to_be_signed = host_port
		#Data to be signed are simple concatenation of following:
		# - service_id as string in the form 'host:port'
		#Then, for each 'certificate' element, following attributes
		#(ints are network order):
		# - DER encoded cert body, uint32 start, uint32 end
		
		dom_impl = getDOMImplementation() 
		new_doc = dom_impl.createDocument(None, "notary_reply", None) 
		top_element = new_doc.documentElement
		top_element.setAttribute("version", "1")
		top_element.setAttribute("sig_type", "rsa-sha256")
	
		for ee_cert in ee_certs:
			cert_elem = new_doc.createElement("certificate")
			top_element.appendChild(cert_elem)
			
			cert_elem.setAttribute("body", base64.standard_b64encode(ee_cert.cert))
			to_be_signed += ee_cert.cert
			
			cert_elem.setAttribute("start", str(ee_cert.start_ts))
			cert_elem.setAttribute("end", str(ee_cert.end_ts))
			to_be_signed += struct.pack("!2I", ee_cert.start_ts, ee_cert.end_ts)
			
		sig = self.sign_rsa_base64(to_be_signed, digest="sha256")
		top_element.setAttribute("sig", sig)
		
		cherrypy.response.headers['Content-Type'] = 'text/xml'
		
		return new_doc.toprettyxml()
	
	@cherrypy.expose
	def refresh_scan(self, host=None, port=None, **kwargs):
		"""Force fresh scan of service. If service has been recently
		scanned, nothing is done. "Recently" currently means 10 minutes.
		
		@param host: host to scan
		@param port: port to scan
		
		HTTP return code:
			202 - scan scheduled
			200 - not scanning, recent enough result exists
			404 - scan not scheduled (likely due to queue full)
		"""
		if (host is None or port is None):
			raise cherrypy.HTTPError(400)
		
		service_id = notary_common.ObservedServer(str(host + ":" + port))
		logger.info("Refresh for '%s'" % service_id)
		
		cursor = db.Db.cursor()
		sql = """SELECT 1 FROM observations_view
				WHERE host = %s AND port = %s
				AND end_time > NOW() - INTERVAL '10 minutes'
				LIMIT 1
			"""
		sql_data = (service_id.host, service_id.port)
		
		try:
			cursor.execute(sql, sql_data)
			row = cursor.fetchone()
			
			if not row: #no recent scan
				scanned = self.launch_on_demand_probe(service_id)
				if not scanned:
					raise cherrypy.HTTPError(404)
				cherrypy.response.status = 202
				
			#if recent row exists, default HTTP 200 is returned
		finally:
			db.Db.commit()
		
		return
	

class OnDemandScanThread(threading.Thread):
	"""On-demand scanner for unknown services."""

	def __init__(self, timeout_sec, source_queue, result_queue, scanned_set):
		"""Initialize with source queue to read from and result queue
		to put results in.
		
		@param timeout_sec: timeout for scan
		@param source_queue: Queue.Queue object storing ObservedServer
		objects
		@param result_queue: Queue.Queue object where tuples of
		(notary_common.ObservedServer, notary_common.Observation) will
		be put as result of scan
		@param scanned_set: notary_common.ScannedSet storing service_ids
		to be scanned
		"""
		self.timeout_sec = timeout_sec
		self.source_queue = source_queue
		self.result_queue = result_queue
		self.scanned_set = scanned_set
		threading.Thread.__init__(self)

	def run(self):
		while True:
			sid = self.source_queue.get()
			
			try: 
				fp = attempt_observation_for_service(sid, self.timeout_sec)
				self.result_queue.put((sid,fp))
			except Exception, e:
				logger.info("Failed to scan %s: %s" % (sid, e))
				self.scanned_set.remove(sid)
				
			self.source_queue.task_done()



if __name__ == "__main__":

	if len(sys.argv) != 2:
		print "usage: <notary-config-file>" 
		exit(1) 
	
	config.config_initialize(sys.argv[1])
	db.db_initialize(config.Config)
	
	logger = create_logger(config.Config.app_log, config.Config.app_loglevel)
	notary_common.set_logger(logger)
	
	#Queue for on-demand requests for new services
	on_demand_queue = Queue.Queue(maxsize=50)
	result_queue = Queue.Queue(maxsize=1000)
	#Synchronized set to prevent adding services that are being scanned/stored
	scanned_set = notary_common.ScannedSet()
	
	start_on_demand_threads(on_demand_queue, result_queue, scanned_set)
	
	
	#Daemonizer(cherrypy.engine).subscribe()
	cherrypy.quickstart(
		NotaryHTTPServer(config.Config, on_demand_queue, scanned_set),
		"/", config.Config.cherrypy_config
		)
	
	logger.info("Waiting for storage threads to finish...")
	result_queue.join()
	logger.info("Storage threads finished, closing down")
