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

# Testing script for get_certs feature. Little copy-pasta from simple_client.

import sys
import traceback
import base64
import urllib
import struct

from M2Crypto import BIO, RSA, EVP
from xml.dom.minidom import parseString

def fetch_certs_xml(notary_server, notary_port, service_id): 
	host, port = service_id.split(":")
	url = "http://%s:%s/get_certs?host=%s&port=%s" % (notary_server, notary_port, host,port)
	url_file = urllib.urlopen(url)
	xml_text = url_file.read()
	code = url_file.getcode()
	return (code,xml_text)
	
def verify_certs_signature(service_id, xml_text, notary_pub_key_text):
	doc = parseString(xml_text)
	root = doc.documentElement
	sig_to_verify = base64.standard_b64decode(root.getAttribute("sig"))
	
	to_verify = service_id
	cert_elements = root.getElementsByTagName("certificate")
	
	for cert_elem in cert_elements:
		cert = base64.standard_b64decode(cert_elem.getAttribute("body"))
		to_verify += cert
		
		start_ts = int(cert_elem.getAttribute("start"))
		end_ts = int(cert_elem.getAttribute("end"))
		to_verify += struct.pack("!2I", start_ts, end_ts)
		
	
	bio = BIO.MemoryBuffer(notary_pub_key_text)
	rsa_pub = RSA.load_pub_key_bio(bio)
	pubkey = EVP.PKey()
	pubkey.assign_rsa(rsa_pub)

	pubkey.reset_context(md='sha256')
	pubkey.verify_init()
	pubkey.verify_update(to_verify)
	return pubkey.verify_final(sig_to_verify)

if len(sys.argv) not in [4,5]:
	print "usage: %s <service-id> <notary-server> <notary-port> [notary-pubkey]" % sys.argv[0]
	exit(1)  


notary_pub_key = None
if len(sys.argv) == 5: 
	notary_pub_key_file = sys.argv[4] 
	notary_pub_key = open(notary_pub_key_file,'r').read() 

try: 
	code, xml_text = fetch_certs_xml(sys.argv[2],int(sys.argv[3]), sys.argv[1])
	if code == 404: 
		print "Notary has no results"
	elif code != 200: 
		print "Notary server returned error code: %s" % code
except Exception, e:
	print "Exception contacting notary server:" 
	traceback.print_exc(e)
	exit(1) 

print 50 * "-"
print "XML Response:" 
print xml_text

print 50 * "-"

if notary_pub_key:
	if not verify_certs_signature(sys.argv[1].lower(), xml_text, notary_pub_key):
		print "Signature verify failed.  Results are not valid"
		exit(1)  
else: 
	print "Warning: no public key specified, not verifying notary signature" 

