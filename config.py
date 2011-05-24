from ConfigParser import SafeConfigParser


Config = None #singleton NotaryServerConfig instance

class NotaryServerConfig(object):
	"""Configuration parser for notary server"""

	def __init__(self, filename):
		"""Parses supplied config file, see notary.config.sample
		@raises ConfigParser.Error if entries are badly formed or missing
		"""
		parser = SafeConfigParser()
		parser.read(filename)

		self.db_host = parser.get("database", "host")
		self.db_port = parser.getint("database", "port")
		self.db_user = parser.get("database", "user")
		self.db_password = parser.get("database", "password")
		self.db_name = parser.get("database", "dbname")
		self.db_min_conn = parser.getint("database", "min_connections")
		self.db_max_conn = parser.getint("database", "max_connections")

		self.keyfile = parser.get("keys", "private")

		self.use_sni = parser.getboolean("server", "use_sni")

def config_initialize(filename):
	"""Initializes Config singleton object using the specifiled filename
	@paramfilename: config filename"""
	
	global Config
	Config = NotaryServerConfig(filename)


