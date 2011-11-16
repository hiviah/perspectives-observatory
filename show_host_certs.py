#!/usr/bin/env python
#   This file is part of the Perspectives Notary Server
#
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

# Simple viewer for certificate chains. Given observation id in ee_certs table,
# prints out whole cert chain for that cert piping it through openssl.

import sys
import time
from datetime import datetime
import shlex
import subprocess
import hashlib

import db
import config
import notary_common

if len(sys.argv) < 3:
	print >> sys.stderr, "show_chain.py <notary.config> <hostname>"
	sys.exit(1)

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

host = sys.argv[2]

cursor = db.Db.cursor()

sql = "SELECT certificate FROM observations_view WHERE host=%s"
cursor.execute(sql, (host,))
rows = cursor.fetchall()
db.Db.commit()

if not rows:
	sys.exit("No certificate for that host")

ee_certs = [str(row['certificate']) for row in rows]

#cmd = shlex.split("openssl x509 -inform der -noout -text")
cmd = shlex.split("openssl x509 -inform der -text")
print "%d row(s) for host %s" % (len(ee_certs), host)
for cert in ee_certs:
	p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	(cout, cerr) = p.communicate(cert)
	print cout
	print "** SHA1:", hashlib.sha1(cert).hexdigest(), "MD5:", hashlib.md5(cert).hexdigest()
	print "-"*20
	p.wait()



