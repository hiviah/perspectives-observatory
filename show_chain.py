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
	print >> sys.stderr, "show_chain.py <notary.config> <ee_cert_id_from_db>"
	sys.exit(1)

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

ee_cert_id = int(sys.argv[2])

cursor = db.Db.cursor()

sql = "SELECT certificate FROM ee_certs WHERE id=%s LIMIT 1"
cursor.execute(sql, (ee_cert_id,))
row = cursor.fetchone()
db.Db.commit()

if not row:
	sys.exit("No certificate by that id")

ee_cert = str(row['certificate'])
ca_certs = notary_common.get_ca_chain(ee_cert_id)

cmd = shlex.split("openssl x509 -inform der -noout -text")
for cert in [ee_cert] + ca_certs:
	p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	(cout, cerr) = p.communicate(cert)
	print cout
	print "** SHA1:", hashlib.sha1(cert).hexdigest(), "MD5:", hashlib.md5(cert).hexdigest()
	print "-"*20
	p.wait()



