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

from datetime import datetime, timedelta
from optparse import OptionParser

import config
import db

# This script generates a file of services ids
# indicating when the last time the notary successfully observed
# a key from that service.  The first parameter points to the
# notary's database file.  The last two
# parameters filter the set of service ids printed based on the
# last observation date.  If 'newer'' is provided, the script will
# only print services with an observation newer than 'days' days.
# If 'older' is provided, the script will print only service ids
# with a MOST RECENT observation that is older than 'days' days.
# Thus, the script can be used to either generate a list of all services
# considered 'live' and of all services considered 'dead'.


parser = OptionParser("Usage: list_service_ids.py [options] notary.config")
parser.add_option("-b", "--blacklist",
	action="store", dest="blacklist",
	help="file with hostnames to skip, one per line")
parser.add_option("-o", "--older",
	action="store", dest="older", metavar="N", type="int",
	help="hosts whose observations are older than N days")
parser.add_option("-n", "--newer",
	action="store", dest="newer", metavar="N", type="int",
	help="hosts whose observations are newer than N days")

(options, args) = parser.parse_args()

if len(args) < 1:
	parser.error("Missing configuration file argument")

if options.newer is not None and options.older is not None:
	parser.error("Only one of --newer/--older can be used")

if options.newer is not None:
	threshold_time = datetime.now() - timedelta(days=int(options.newer))
if options.older is not None:
	threshold_time = datetime.now() - timedelta(days=int(options.older))
	

config.config_initialize(args[0])
db.db_initialize(config.Config)

#Use named (server-side) cursor to avoid too much memory consumed by normal
#cursor. Unnamed cursor would load all results into memory even before
#fetchone() is called (psycopg behaves this way).
cursor = db.Db.cursor(name="list_services")

blacklist = set()
blacklist_fname = options.blacklist
if blacklist_fname:
	with file(blacklist_fname) as blacklist_file:
		blacklist = set([line.rstrip() for line in blacklist_file])


try:
	if options.newer is None and options.older is None: 
		sql = "SELECT host, port FROM services"
		cursor.execute(sql)
	elif options.older is not None:
		sql = """SELECT host, port FROM services
				WHERE NOT EXISTS
					(SELECT 1 FROM ee_certs WHERE
						services.id = ee_certs.service_id
						AND end_time > %s)
			"""
		cursor.execute(sql, (threshold_time,))
	else: #options.newer is not None
		sql = """SELECT host, port FROM services
				WHERE EXISTS
					(SELECT 1 FROM ee_certs WHERE
						services.id = ee_certs.service_id
						AND end_time > %s)
			"""
		cursor.execute(sql, [ threshold_time ] )
		
	while True:
		rows = cursor.fetchmany(20000)
		if not rows:
			break
		for row in rows:
			if row['host'] not in blacklist:
				print "%s:%s" % (row['host'] , row['port'])
finally:
	cursor.close()
	db.Db.commit()
