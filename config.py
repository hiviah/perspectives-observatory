#   This file is part of the Perspectives Notary Server
#
#   Copyright (C) 2011 Ondrej Mikle
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

from ConfigParser import SafeConfigParser

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
		self.db_pass = parser.get("database", "pass")
		self.db_name = parser.get("database", "dbname")

		self.keyfile = parser.get("keys", "private")

		self.use_sni = parser.get("scanning", "use_sni")