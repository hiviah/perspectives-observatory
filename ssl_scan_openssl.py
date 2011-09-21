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

import subprocess
import sys
import traceback
import notary_common 

import config
import db

# note: timeout is ignored for now
def attempt_observation_for_service(service_id, timeout):  
	"""Attempt observation of SSL service.
	@param service_id: instance of notary_common.ObservedServer
	@param timeout: not supported, openssl has some hardwired timeout
	@returns: instance of notary_common.Observation
	"""
	cmd1_args = ["openssl","s_client","-connect", service_id.host_port ] 
	if (config.Config.use_sni): 
		cmd1_args += [ "-servername", service_id.host ]  

	p1 = subprocess.Popen(cmd1_args, stdin=file("/dev/null", "r"), stdout=subprocess.PIPE,
		stderr=file("/dev/null", "w"))
	p2 = subprocess.Popen(["openssl","x509","-outform","der"],
		stdin=p1.stdout, stdout=subprocess.PIPE, stderr=file("/dev/null", "w"))

	#output is DER-encoded cert
	output = p2.communicate()[0].strip()
	p1.wait()
	p2.wait()

	if p2.returncode != 0:
		raise Exception("ERROR: Could not fetch/decode certificate for '%s'" % service_id.host_port) 

	return notary_common.Observation([output])


if __name__ == "__main__":


	if len(sys.argv) < 3:
		print >> sys.stderr, "ERROR: usage: <service-id> config_file"
		exit(1)

	service_id = notary_common.ObservedServer(sys.argv[1])

	config.config_initialize(sys.argv[2])
	db.db_initialize(config.Config)

	fp = attempt_observation_for_service(service_id, 10) 

	print "Successful scan complete: '%s' has key '%s' " % (service_id,fp)
	
	if len(sys.argv) == 3: 
		notary_common.report_observation(service_id, fp) 
	else: 
		print "INFO: no database specified, not saving observation"

		
