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

import sys
import os
import re
from datetime import datetime, timedelta

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

def usage_and_exit(): 
	print >> sys.stderr, "ERROR: usage: <notary.config> <all|older|newer> <days>"
	exit(1)

if len(sys.argv) == 4: 
	if not (sys.argv[2] == "older" or sys.argv[2] == "newer"): 
		usage_and_exit()
	threshold_time = datetime.now() - timedelta(days=int(sys.argv[3]))
elif len(sys.argv) == 3: 
	if not sys.argv[2] == "all": 
		usage_and_exit()
else: 
	usage_and_exit()
	

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

#Use named (server-side) cursor to avoid too much memory consumed by normal
#cursor. Unnamed cursor would load all results into memory even before
#fetchone() is called (psycopg behaves this way).
cursor = db.Db.cursor(name="list_services")


try:
	if sys.argv[2] == "all": 
		sql = "SELECT host, port FROM services"
		cursor.execute(sql)
	elif sys.argv[2] == "older": 
		sql = """SELECT host, port FROM services
				WHERE NOT EXISTS
					(SELECT 1 FROM ee_certs WHERE
						services.id = ee_certs.service_id
						AND end_time > %s)
			"""
		cursor.execute(sql, (threshold_time,))
	else: 
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
			print "%s:%s" % (row['host'] , row['port'])
finally:
	cursor.close()
	db.Db.commit()
