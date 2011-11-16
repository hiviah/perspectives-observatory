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
import base64

import db
import config
import notary_common

if len(sys.argv) < 3:
	print >> sys.stderr, "show_chain.py <notary.config> <file_with_ee_cert_ids>"
	sys.exit(1)

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

id_file = file(sys.argv[2])

cursor = db.Db.cursor()

for line in id_file:
	ee_cert_id = int(line.rstrip())
	sql = "SELECT certificate FROM ee_certs WHERE id=%s LIMIT 1"
	cursor.execute(sql, (ee_cert_id,))
	row = cursor.fetchone()
	db.Db.commit()

	if not row:
		print >> sys.stderr, "No certificate with id %d" % ee_cert_id

	ee_cert = str(row['certificate'])
	ca_certs = notary_common.get_ca_chain(ee_cert_id)
	encoded_chain = [base64.b64encode(cert) for cert in [ee_cert] + ca_certs]
	print "|".join([str(ee_cert_id)] + encoded_chain)

