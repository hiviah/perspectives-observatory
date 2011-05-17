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

import time 
import os
import sys
import subprocess
import re
import hashlib
import binascii

import db

SSL_SCAN="ssl_scan_openssl.py" 
SSH_SCAN="ssh_scan_openssh.py"

class ObservedServer(object):
	"""Represents scanned server - host, port, service"""

	#syntax for "host:port,service"
	_syntax_re = re.compile("([^,:]+):(\d+),(\d+)")

	def __init__(self, service_id):
		"""Parse service_id string of form "host:port,service"
		@raises ValueError if service_id is badly formed"""

		m = self._syntax_re.match(service_id)
		if m is None:
		    raise ValueError("Service_id string '%s' is malformed" % service_id)
		
		self.host = m.group(1)
		self.port = int(m.group(2))
		self.service_type = int(m.group(3))

	def __str__(self):
		"""Returns the old form of "host:port,service" """
		return "%s:%s,%s" % (self.host, self.port, self.service_type)

	def __repr__(self):
		"""repr() form for debugging"""
		return "<ObservedServer '%s'>" % str(self)

	@property
	def host_port(self):
		"""Return connect string in 'host:port' format"""
		return "%s:%s" % (self.host, self.port)

class Observation(object):
	"""Class for storing observed fingeprints from various hash algorithms.
	
	Accessing the hashes is done by using one of the attributes named in
	_supported_hashes, e.g. if obs is Observation instance, obs.sha1 will
	return its sha1 hash, if any was set, otherwise it's None."""

	_supported_hashes = ('md5', 'sha1', 'sha256', 'sha512')

	def __init__(self, cert):
		"""Initialize with certificate, computes the hashes in _supported_hashes
		which are then stored as attributes as binary strings.
		
		@param cert: certificate as string in DER encoding (validity is not checked)
		"""
		self.cert = cert
		for hash_algo in self._supported_hashes:
			hash = hashlib.new(hash_algo)
			hash.update(cert)
			setattr(self, hash_algo, hash.digest())
	
	def __str__(self):
		return ",".join(["(%s: %s)" % (h, binascii.hexlify(getattr(self, h))) for h in self._supported_hashes ])

# The start_scan_probe seems to be deprecated, only simple_scanner.py uses it
# and it is not mentioned in README at all.
def start_scan_probe(sid, notary_db): 
	"""Start probe for given service, store resulting fingerprint in database
	@param sid: instance of ObservedServer"""
	if sid.service_type == "2": 
		first_arg = SSL_SCAN 
	elif sid.service_type == "1": 
		first_arg = SSH_SCAN 
	else: 
		print >> sys.stderr, "ERROR: invalid service_type for '%s'" % sid
		return

	#TODO: why do we need subprocess for this? why not call the method in this process?
	nul_f = open(os.devnull,'w') 
	return subprocess.Popen(["python", first_arg, str(sid), notary_db], stdout=nul_f , stderr=subprocess.STDOUT )

def report_observation(service_id, observation): 
	"""Insert or update observation and commit to DB
	@param service_id: ObservedServer instance
	@param observation: Observation instance"""

	cur_time = int(time.time()) 
	cur = db.Db.cursor()

	#Select last fingerprint and check if it's the same.
	#If same, update end timestamp, otherwise insert new observation
	sql = """SELECT id, md5, end_ts from observations_view
			WHERE host = %s 
				AND port = %s
				AND service_type = %s
			ORDER BY end_ts DESC
			LIMIT 1
		    """
	sql_data = (service_id.host, service_id.port, service_id.service_type)

	cur.execute(sql, sql_data)

	most_recent_md5 = None
	most_recent_id = None
	row = cur.fetchone()
	
	#checking for "freshness" is done by MD5 checking since we won't necessarily
	#have other hashes (like it was in original code)
	if row is not None:
		most_recent_md5 = str(row['md5'])
		most_recent_id = row['id']

	if most_recent_md5 == observation.md5: 
		# this key was also the most recently seen key before this observation.
		# just update the observation row to set the timespan 'end' value to the 
		# current time.
		sql = """UPDATE observations 
				SET end_time = to_timestamp(%s)
				WHERE id = %s
			"""
		sql_data = (cur_time, most_recent_id)
		cur.execute(sql, sql_data)
	else: 
		# key has changed or no observations exist yet for this service_id.  Either way
		# add a new entry for this key with timespan start and end set to the current time
		sql = """INSERT INTO observations (host, port, service_type, start_time, end_time, md5, sha1, certificate) 
				VALUES (%s, %s, %s, to_timestamp(%s), to_timestamp(%s), %s, %s, %s)
			"""
		sql_arg = (service_id.host, service_id.port, service_id.service_type,
			cur_time, cur_time, buffer(observation.md5), buffer(observation.sha1),
			buffer(observation.cert))
		
		cur.execute(sql, sql_arg)
		
		if most_recent_id:
			# if there was a previous key, set its 'end' timespan value to be current 
			# time minus one seconds 
			sql = """UPDATE observations
					SET end_time = to_timestamp(%s)
					WHERE id = %s
				"""
			sql_arg = (cur_time-1, most_recent_id)
			cur.execute(sql, sql_arg)

	db.Db.commit()


