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

import re
import hashlib
import binascii
from datetime import datetime, timedelta

import db

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

	def __str__(self):
		"""Returns the old form of "host:port" """
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

	@property
	def host_port(self):
		"""Return connect string in 'host:port' format"""
		return "%s:%s" % (self.host, self.port)

class Observation(object):
	"""Class for storing observed fingeprints from various hash algorithms.
	
	Accessing the hashes is done by using one of the attributes named in
	_supported_hashes, e.g. if obs is Observation instance, obs.sha1 will
	return its sha1 hash, if any was set, otherwise it's None. The hashes
	correspond to the leaf (server) certificates."""

	_supported_hashes = ('md5', 'sha1')
	
	__hash__ = None

	def __init__(self, cert_chain):
		"""Initialize with certificate, computes the hashes in _supported_hashes
		which are then stored as attributes as binary strings.
		
		@param cert_chain: certificates chain as string list in DER encoding
		(validity is not checked). Must be ordered from index 0 being
		the leaf (server) cert, with increasing indices being in the
		chain order. At least one certificate must be present in the list.
		"""
		if len(cert_chain) == 0:
			raise ValueError("Empty certificate chain")
		self.cert_chain = list(cert_chain)
		for hash_algo in self._supported_hashes:
			hash = hashlib.new(hash_algo)
			hash.update(cert_chain[0])
			setattr(self, hash_algo, hash.digest())
	
	def ee_cert(self):
		"""Returns DER encoded leaf (EE) certificate"""
		return self.cert_chain[0]
	
	def ca_certs(self):
		"""Returns list of DER encoded CA certificates (smaller index
		is closer to leaf, higher index closer to root)
		"""
		return self.cert_chain[1:]
	
	def __str__(self):
		return ",".join(["(%s: %s)" % (h, binascii.hexlify(getattr(self, h))) for h in self._supported_hashes ])

def store_service_id(service_id):
	"""Stores service_d in 'services' table unless already present.To be run
	inside a transaction.
	
	@param service_id: ObservedServer instance
	@returns: stored service id
	@raises psycopg2.DatabaseError on DB error
	"""
	sql = """SELECT id FROM services WHERE host=%s AND port=%s"""
	cursor = db.Db.cursor()
	
	sql_data = (service_id.host, service_id.port)
	cursor.execute(sql, sql_data)
	row = cursor.fetchone()
	if row:
		return row['id']
	
	sql = """INSERT INTO services (host, port) VALUES (%s, %s)
			RETURNING id
		"""
	cursor.execute(sql, sql_data)
	return cursor.fetchone()['id']

def get_most_recent_ee_cert(service_id):
	"""Get most recent observation of EE certficate for service_id.
	To be run inside transaction.
	
	@param service_id: instance of ObservedServer
	@returns: tuple (id, certificate) if found as (int, str),
	otherwise (None, None)
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	
	sql = """SELECT id, certificate from observations_view
			WHERE host = %s	AND port = %s
			ORDER BY end_ts DESC
			LIMIT 1
			"""
	sql_data = (service_id.host, service_id.port)

	cursor.execute(sql, sql_data)
	row = cursor.fetchone()
	
	if row is not None:
		return (row['id'], str(row['certificate']))
	else:
		return (None, None)
	
def store_ca_chain_certs(observation):
	"""Stores CA certificates from observation into 'ca_certs' table
	unless already present. To be run inside transaction.
	
	@param observation: Observation instance
	@returns: list of ids of stored CA certs from 'ca_certs' table
	@raises psycopg2.DatabaseError on DB error
	"""
	cert_ids = []
	cursor = db.Db.cursor()
	
	#md5(cert) is used in query because index is built over md5(cert)
	sql_get = """
		SELECT id, certificate FROM ca_certs
			WHERE md5(certificate) = md5(%s)
		"""
	sql_insert = """INSERT INTO ca_certs (certificate) VALUES (%s) RETURNING id"""
	
	for ca_cert in observation.ca_certs():
		#first try to find cert, most times at most one row will be
		#returned from the following query
		sql_data = (ca_cert,)
		cursor.execute(sql_get, sql_data)
		rows = cursor.fetchall()
		
		id = None
		for row in rows:
			if ca_cert == str(row['certificate']):
				id = row['id']
				break
		
		#insert if not present
		if not id:
			sql_data = (ca_cert,)
			cursor.execute(sql_insert, sql_data)
			id = cursor.fetchone()['id']
		
		cert_ids.append(id)
		
	return cert_ids

def store_ca_chain(ee_cert_id, ca_cert_ids):
	"""Store the relation of EE cert and CA certs belonging to the same
	certificate chain represented in table 'ee_cert_x_ca_certs'.
	To be run inside transaction.
	
	@param ee_cert_id: id of EE leaf certificate in chain in 'ee_certs' table
	@param ca_cert_ids: ids of CA certificates in 'ca_certs' table
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	sql = """INSERT INTO ee_cert_x_ca_certs (seq_num, ee_cert_id, ca_cert_id)
			VALUES (%s, %s, %s)
		"""
	
	chain_idx = 0 #goes upwards then getting closer to root cert
	for ca_cert_id in ca_cert_ids:
		sql_data = (chain_idx, ee_cert_id, ca_cert_id)
		cursor.execute(sql, sql_data)
		chain_idx +=1

def update_ee_cert_timestamp(ee_cert_id, timestamp):
	"""Update end_time of cert in 'ee_cert' table.
	
	@param ee_cert_id: id of EE cert in 'ee_cert' table
	@param timestamp: end_time will be updated to this timestamp
	@raises psycopg2.DatabaseError on DB error
	"""
	cursor = db.Db.cursor()
	sql = """UPDATE ee_certs
			SET end_time = %s
			WHERE id = %s
		"""
	sql_data = (timestamp, ee_cert_id)
	cursor.execute(sql, sql_data)
	
def store_ee_cert(observation, db_service_id, timestamp):
	"""Store EE cert from observation.
	
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
	cursor.execute(sql, sql_data)
	
	return cursor.fetchone()['id']
	
def report_observation(service_id, observation):
	"""Insert or update observation and commit to DB
	@param service_id: ObservedServer instance
	@param observation: Observation instance
	
	@raises psycopg2.DatabaseError: in case of transaction collision (e.g.
	inserting multiple observations with same parts of chain). In such
	case the whole transaction is rolled back.
	"""
	#TODO: this transaction is rather long, it might be a good idea to split
	#it into several smaller transactions at the cost of possibly losing
	#the ties between certs in chain or losing certs higher in the chain
	cur_time = datetime.now()

	#Select last certificate and check if it's the same.
	#If same, update end timestamp, otherwise insert new observation
	try:
		(most_recent_id, most_recent_cert) = get_most_recent_ee_cert(service_id)
		
		if most_recent_cert == observation.ee_cert():
			# this key was also the most recently seen key before this observation.
			# just update the observation row to set the timespan 'end' value to the 
			# current time.
			update_ee_cert_timestamp(most_recent_id, cur_time)
		else: 
			# cert has changed or no observations exist yet for this service_id.  Either way
			# add a new entry for this key with timespan start and end set to the current time
			db_service_id = store_service_id(service_id)
			ee_cert_id = store_ee_cert(observation, db_service_id, cur_time)
			ca_cert_ids = store_ca_chain_certs(observation)
			store_ca_chain(ee_cert_id, ca_cert_ids)
			
			if most_recent_id:
				# if there was a previous key, set its 'end' timespan value to be current 
				# time, minus 1 second (like it was in original perspectives)
				update_ee_cert_timestamp(most_recent_id, cur_time-timedelta(seconds=1))

	finally:
		db.Db.commit()


