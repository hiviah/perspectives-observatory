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

import re
import hashlib
import threading
from datetime import datetime

import db

import logging
logger = logging

def set_logger(logger_object):
	"""Set the logger object used for logging in this module. It has to have
	interface like python's built-in 'logging' module or logging.Logger.
	The whole deal with this is the possibility to have logger that does
	not interfere with cherrypy and psycopg2 logging.
	"""
	global logger
	logger = logger_object

class ScannedSet(object):
	"""Synchronized set keeping track of services being scanned. Its purpose
	is to prevent dispatching unnecessary probes if service is already
	in queue or being scanned (FF extension for some reason sends 3 requests
	often faster than we get result).
	"""
	
	def __init__(self):
		self._lock = threading.Lock()
		self._scanned_set = set()
	
	def insert(self, service_id):
		"""Insert atomically service_id into set.
		@param service_id: ObservedServer instance
		@returns: True if the service was newly added or False if already
		present
		"""
		with self._lock:
			if service_id in self._scanned_set:
				return False
			self._scanned_set.add(service_id)
			return True
	
	def remove(self, service_id):
		"""Remove service_id from set.
		@param service_id: ObservedServer instance
		"""
		with self._lock:
			self._scanned_set.remove(service_id)
		
	
class StorageThread(threading.Thread):
	"""Thread storing scanned observations into database."""
	
	def __init__(self, result_queue, scanned_set=None):
		"""Initialize thread to store data from result queue.
		
		@param result_queue: a Queue.Queue instance, where each item
		read is tuple (notary_common.ObservedServer, notary_common.Observation)
		
		@param scanned_set: must be None or ScannedSet instance. If not
		None, upon successful storing of service_id into DB the service_id
		is removed from the scanned_set
		"""
		self.result_queue = result_queue
		self.scanned_set = scanned_set
		threading.Thread.__init__(self)
	
	def run(self):
		"""Run thread. The threads wakes up when result queue gets a
		result put in, stores it in DB, then waits again until queue
		has something to store.
		"""
		while True:
			scan_result = self.result_queue.get()
			(sid, fp) = scan_result
			try:
				report_observation(sid, fp)
				logger.debug("Storing sid %s" % sid)
			except Exception:
				logger.exception("Failed to store result for sid %s" % sid)
			finally:
				self.result_queue.task_done()
				if self.scanned_set:
					self.scanned_set.remove(sid)
		
class ObservedServer(object):
	"""Represents scanned server - host, port, service"""

	#syntax for "host:port"
	_syntax_re = re.compile("([^,:]+):(\d+)")
	
	def __init__(self, service_id):
		"""Parse service_id string of form "host:port,service"
		@raises ValueError if service_id is badly formed"""

		m = self._syntax_re.match(service_id)
		if m is None:
			raise ValueError("Service_id string '%s' is malformed" % service_id)
		
		self.host = (m.group(1)).lower() #force lowercase of hostname
		self.port = int(m.group(2))
		
		if not (self.port > 0 and self.port < 65536):
			raise ValueError("Invalid port in service_id %s" % service_id)

	def old_str(self):
		"""Return as 'host:port,2' string. This is for compatibility
		with old Perspectives code, e.g. for signing XML responses for
		Firefox extension.
		"""
		return "%s:%s,2" % (self.host, self.port)

	def __str__(self):
		"""Returns as 'host:port' string."""
		return "%s:%s" % (self.host, self.port)

	def __repr__(self):
		"""repr() form for debugging"""
		return "<ObservedServer '%s'>" % str(self)
	
	def _id(self):
		"""Returns tuple to be used for __hash__, __eq__, etc."""
		return (self.host, self.port)
		
	def __hash__(self):
		return hash(self._id())
	
	def __eq__(self, other):
		return self._id() == other._id()
	
	def __ne__(self, other):
		return not self.__eq__(other)
	
	def __cmp__(self, other):
		return cmp(self._id(), other._id())

class Observation(object):
	"""Class for storing scanned certificate chains.
	"""
	
	__hash__ = None

	def __init__(self, cert_chain):
		"""Initialize with certificate list.
		
		@param cert_chain: certificates chain as string list in DER encoding
		(validity is not checked). Must be ordered from index 0 being
		the leaf (server) cert, with increasing indices being in the
		chain order. At least one certificate must be present in the list.
		"""
		if len(cert_chain) == 0:
			raise ValueError("Empty certificate chain")
		self.cert_chain = list(cert_chain)
	
	def ee_cert(self):
		"""Returns DER encoded leaf (EE) certificate"""
		return self.cert_chain[0]
	
	def ca_certs(self):
		"""Returns list of DER encoded CA certificates (smaller index
		is closer to leaf, higher index closer to root)
		"""
		return self.cert_chain[1:]
	
	def __str__(self):
		return "Observation: sha1: %s" % hashlib.sha1(self.ee_cert()).hexdigest()

class EECert(object):
	"""Represents observation of leaf certificate from DB view observations_view.
	"""
	
	def __init__(self, id, cert, start_ts, end_ts):
		self.id = id
		self.cert = cert
		self.start_ts = start_ts
		self.end_ts = end_ts

def store_service_id(service_id):
	"""Stores service_d in 'services' table unless already present. Commits
	transaction.
	
	@param service_id: ObservedServer instance
	@returns: stored service id
	@raises psycopg2.DatabaseError on DB error
	"""
	sql = """SELECT id FROM services WHERE host=%s AND port=%s"""
	cursor = db.Db.cursor()
	
	sql_data = (service_id.host, service_id.port)
	
	try:
		cursor.execute(sql, sql_data)
		row = cursor.fetchone()
		if row:
			return row['id']
		
		sql = """INSERT INTO services (host, port) VALUES (%s, %s)
				RETURNING id
			"""
		cursor.execute(sql, sql_data)
		return cursor.fetchone()['id']
	finally:
		db.Db.commit()

def get_ee_certs(service_id):
	"""Get all observations of EE certs for given service_id.
	Commits transaction.
	
	@param service_id: instance of ObservedServer
	@returns: list of EECert instances
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	
	sql = """SELECT id, certificate, start_ts, end_ts from observations_view
			WHERE host = %s	AND port = %s
			"""
	sql_data = (service_id.host, service_id.port)
	
	try:
		cursor.execute(sql, sql_data)
		rows = cursor.fetchall()
		
		return [EECert(row['id'], str(row['certificate']), row['start_ts'], row['end_ts'])
			for row in rows]
	finally:
		db.Db.commit()
	
	
def store_ca_chain_certs(observation):
	"""Stores CA certificates from observation into 'ca_certs' table
	unless already present. Commits transaction.
	
	@param observation: Observation instance
	@returns: list of ids of stored CA certs from 'ca_certs' table
	@raises psycopg2.DatabaseError on DB error
	"""
	cert_ids = []
	cursor = db.Db.cursor()
	
	#md5(cert) is used in query because index is built over md5(cert)
	sql_get = """
		SELECT id, certificate FROM ca_certs
			WHERE md5(certificate) = %s
		"""
	sql_insert = """INSERT INTO ca_certs (certificate) VALUES (%s) RETURNING id"""
	
	for ca_cert in observation.ca_certs():
		#first try to find cert, most times at most one row will be
		#returned from the following query
		ca_cert_md5 = hashlib.md5(ca_cert).hexdigest()
		sql_data = (ca_cert_md5,)
		
		try:
			#The lock prevents insertion of non-unique CA certs
			#since we can't have unique index on bytea certificate
			#field.
			#cursor.execute("LOCK TABLE ca_certs");
			cursor.execute(sql_get, sql_data)
			rows = cursor.fetchall()
			
			id = None
			for row in rows:
				if ca_cert == str(row['certificate']):
					id = row['id']
					break
			
			#insert if not present
			if not id:
				sql_data = (buffer(ca_cert),)
				cursor.execute(sql_insert, sql_data)
				id = cursor.fetchone()['id']
			
			cert_ids.append(id)
		finally:
			db.Db.commit() #commits and unlocks ca_certs table
		
	return cert_ids

def store_ca_chain(ee_cert_id, ca_cert_ids):
	"""Store the relation of EE cert and CA certs belonging to the same
	certificate chain represented in table 'ee_cert_x_ca_certs'.
	Commits the transaction.
	
	@param ee_cert_id: id of EE leaf certificate in chain in 'ee_certs' table
	@param ca_cert_ids: ids of CA certificates in 'ca_certs' table
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	sql = """INSERT INTO ee_cert_x_ca_certs (seq_num, ee_cert_id, ca_cert_id)
			VALUES (%s, %s, %s)
		"""
		
	try:
		chain_idx = 0 #goes upwards then getting closer to root cert
		for ca_cert_id in ca_cert_ids:
			sql_data = (chain_idx, ee_cert_id, ca_cert_id)
			cursor.execute(sql, sql_data)
			chain_idx +=1
	finally:
		db.Db.commit()

def get_ca_chain(ee_cert_id):
	"""Get CA/intermediate certs for chain from observation.
	Commits transaction at the end.
	
	@param ee_cert_id: id of observation in 'ee_certs' table
	@returns: list of DER-encoded CA certificates chaining from the EE cert
	towards root (lower index is closer to EE cert, higher closer towards
	root)
	"""
	cursor = db.Db.cursor()
	sql = """SELECT certificate from ee_cert_x_ca_certs
			INNER JOIN ca_certs ON (ca_cert_id = ca_certs.id)
			WHERE ee_cert_id=%s
			ORDER BY seq_num
		"""
	sql_data = (ee_cert_id,)
	
	try:
		cursor.execute(sql, sql_data)
		rows = cursor.fetchall()
		return [str(row['certificate']) for row in rows]
	finally:
		db.Db.commit()
	
	
def update_ee_cert_timestamp_by_id(ee_cert_id, timestamp):
	"""Update end_time of cert in 'ee_cert' table.
	Commits the transaction.
	
	@param ee_cert_id: id of EE cert in 'ee_cert' table
	@param timestamp: end_time will be updated to this timestamp
	@returns: number of rows updated
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	sql = """UPDATE ee_certs
			SET end_time = %s
			WHERE id = %s
		"""
	sql_data = (timestamp, ee_cert_id)
	try:
		cursor.execute(sql, sql_data)
		return cursor.rowcount
	finally:
		db.Db.commit()
	
def update_ee_cert_timestamp_by_cert(service_id, cert, timestamp):
	"""Update end_time of EE certificate observation for given service and
	certificate. If observation with the specific certificate does not
	exist, nothing is updated. Commits the transaction.
	
	@param service_id: instance of ObservedServer
	@param cert: DER-encoded EE certificate string
	@param timestamp: end_time will be updated to this timestamp
	@return: number of rows updated
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	sql = """SELECT id from services
			WHERE host=%s AND port=%s
		"""
	sql_data = (service_id.host, service_id.port)
	
	try:
		cursor.execute(sql, sql_data)
		row = cursor.fetchone()
		if not row:
			return 0
		
		services_host_id = row['id']
		
		sql = """UPDATE ee_certs
				SET end_time = %s
				WHERE service_id = %s AND certificate=%s
			"""
		sql_data = (timestamp, services_host_id, buffer(cert))
		cursor.execute(sql, sql_data)
		
		return cursor.rowcount
	finally:
		db.Db.commit()
	
def store_ee_cert(observation, db_service_id, timestamp):
	"""Store EE cert from observation.
	Commits the transaction.
	
	@param observation: Observation instance
	@param db_service_id: id of host in 'services' table this observation
	belongs to
	@param timestamp: this time will be used as start_time and end_time
	for the certificate (datetime object)
	@returns: id of stored observation in 'ee_certs' table
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	sql = """INSERT INTO ee_certs (start_time, end_time, certificate, service_id)
			VALUES(%s, %s, %s, %s)
			RETURNING id
		"""
	sql_data = (timestamp, timestamp, buffer(observation.ee_cert()), db_service_id)
	try:
		cursor.execute(sql, sql_data)
		
		return cursor.fetchone()['id']
	finally:
		db.Db.commit()
	
def report_observation(service_id, observation, timestamp=None):
	"""Insert or update observation and commit to DB
	@param service_id: ObservedServer instance
	@param observation: Observation instance
	@param timestamp: instance of datetime - timestamp to record. Current
	time is used if set to None
	
	@raises psycopg2.DatabaseError: in case of transaction collision (e.g.
	inserting multiple observations with same parts of chain). In such
	case the whole transaction is rolled back.
	"""
	#NOTE: the following process is broken down into smaller transactions.
	#Worst case scenario is that e.g. some of the certificates will get
	#stored, but link saying "this EE cert belongs to this chain" may be
	#lost (whereas were it a single transaction, the EE cert would be lost
	#as well).
	update_time = timestamp or datetime.now()

	#To deal with CDN effect (=single host appearing to have multiple
	#certificates because of reverse proxy), update end_time timestamp for
	#observation of host. If no observation with the certificate exists,
	#insert new observation.
	updated_count = update_ee_cert_timestamp_by_cert(service_id,
			observation.ee_cert(), update_time)
	
	if updated_count < 1:
		#We don't update end_time timestamp of the other last
		#seen cert for this service like old Perspectives did.
		#The semantics of end_time should be when the cert was
		#actually last seen, not to attempt having "continuous"
		#timeline in the SVG viewer.
		
		# Observation for service with this cert not seen yet,
		# insert new observation.
		db_service_id = store_service_id(service_id)
		ee_cert_id = store_ee_cert(observation, db_service_id, update_time)
		ca_cert_ids = store_ca_chain_certs(observation)
		store_ca_chain(ee_cert_id, ca_cert_ids)
		
	elif updated_count > 1:
		#There is a remotely small possibility of two identical EE cert
		#for host being stored, but that can be detected easily and
		#cleaned up. Otherwise we'd have to lock 'ee_certs' table since
		#we can't use unique index over bytea. Locking would in turn
		#impact all reads fetched for clients.
		logger.warn("Duplicate EE cert for service '%s'" % service_id)


