"""Usage:
from config import NotaryServerConfig
import db
from db import Db

config = NotaryServerConfig(filename)
db.initialize(config)

#Db is a pool that is used like a singleton
cursor = Db.cursor()
cursor.execute(...)
#do stuff
cursor.close()
Db.commit()
"""

from psycopg2.extras import DictCursor
from psycopg2.pool import PersistentConnectionPool

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

		self.pool = PersistentConnectionPool(
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
		return self.pool.getconn()

	def commit(self):
		"""Commit all the commands in this transaction in this thread's connection"""
		self.connection().commit()

	def rollback(self):
		"""Rollback last transaction on this thread's connection"""
		self.connection().rollback()

def db_initialize(config):
	"""Initialize database connection pool. Once done, the db.Db can
	be used to access connections from various threads.
	@param config: instance of NotaryServerConfig
	"""
	global Db
	Db = DbPool(config)


