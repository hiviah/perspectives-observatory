#   This file is part of the Perspectives Notary Server
#
#   Copyright (C) 2011 Ondrej Mikle, cz.nic
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

"""Usage:
import config
import db

config.config_initialize(filename)
db.db_initialize(config.Config)

#Db is a connection pool that is used like a singleton; one connection per thread
cursor = db.Db.cursor()
cursor.execute(...)
#do stuff
cursor.close()
db.Db.commit()

IMPORTANT: when connection is used in a thread, you need to return it via
db.Db.putconn() upon finishing thread, otherwise the pool won't know it can be
reused. Note that cherrypy itself is threaded with 10 threads default.
"""

import threading

from psycopg2.extras import DictCursor
from psycopg2.pool import ThreadedConnectionPool

Db = None #singleton database connection pool, see db_initialize()

class DbPool(object):
	"""DB class that makes connection transparently. Thread-safe - every
	thread get its own database connection. Not meant to be used directly,
	there is no reason to have more than one instance - global variable Db
	- in this module."""

	def __init__(self, config):
		"""Configures the Db, connection is not created yet.
		@param config: instance of config.NotaryServerConfig."""

		self.host = config.db_host
		self.port = config.db_port
		self.user = config.db_user
		self.password = config.db_password
		self.db_name = config.db_name
		self.min_connections = config.db_min_conn
		self.max_connections = config.db_max_conn

		self.pool = ThreadedConnectionPool(
			minconn = self.min_connections,
			maxconn = self.max_connections,
			host = self.host,
			port = self.port,
			user = self.user,
			password = self.password,
			database = self.db_name)

	def cursor(self):
		"""Creates and returns cursor for current thread's connection.
		Cursor is a "dict" cursor, so you can access the columns by
		names (not just indices), e.g.:

		cursor.execute("SELECT id, name FROM ... WHERE ...", sql_args)
		row = cursor.fetchone()
		id = row['id']
		
		You should close() the cursor and commit() or rollback() when
		done with the transaction."""
		return self.connection().cursor(cursor_factory=DictCursor)
	
	def connection(self):
		"""Return connection for this thread"""
		return self.pool.getconn(id(threading.current_thread()))

	def commit(self):
		"""Commit all the commands in this transaction in this thread's connection"""
		self.connection().commit()

	def rollback(self):
		"""Rollback last transaction on this thread's connection"""
		self.connection().rollback()
	
	def	putconn(self):
		"""Put back connection used by this thread. Necessary upon finishing of
		spawned threads, otherwise new threads won't get connection if the pool
		is depleted."""
		conn = self.connection()
		self.pool.putconn(conn, id(threading.current_thread()))
	
	def close(self):
		"""Close connection."""
		self.connection().close()

def db_initialize(config):
	"""Initialize database connection pool. Once done, the db.Db can
	be used to access connections from various threads.
	@param config: instance of NotaryServerConfig
	"""
	global Db
	Db = DbPool(config)


