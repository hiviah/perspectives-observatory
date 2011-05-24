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

import sys
import os
import re
import time

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
	cur_time = int(time.time()) 
	threshold_sec = int(int(time.time()) - (3600 * 24 * int(sys.argv[3])))
elif len(sys.argv) == 3: 
	if not sys.argv[2] == "all": 
		usage_and_exit()
else: 
	usage_and_exit()
	

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)
cur = db.Db.cursor()


if sys.argv[2] == "all": 
	sql = "SELECT DISTINCT host, port, service_type FROM observations_view"
	cur.execute(sql)
elif sys.argv[2] == "older": 
	sql = """SELECT DISTINCT host, port, service_type FROM observations o
			WHERE NOT EXISTS
				(SELECT 1 FROM observations_view v WHERE
					o.host = v.host and
					o.port = v.port and
					o.service_type = v.service_type and
					end_ts > %s)
		"""
	cur.execute(sql, (threshold_sec,))
else: 
	sql = """SELECT DISTINCT host, port, service_type FROM observations_view
			WHERE end_ts > %s
		"""
	cur.execute(sql, [ threshold_sec ] )
	
for row in cur.fetchall():
	print "%s:%s,%s" % (row['host'] , row['port'], row['service_type'])
