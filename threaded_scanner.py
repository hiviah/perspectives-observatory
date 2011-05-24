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
import time 
import socket
import struct
import sys
import notary_common 
import traceback 
import threading
import errno
from ssl_scan_sock import attempt_observation_for_service, SSLScanTimeoutException, SSLAlertException

import config
import db

# TODO: more fine-grained error accounting to distinguish different failures
# (dns lookups, conn refused, timeouts).  Particularly interesting would be
# those that fail or hang after making some progress, as they could indicate
# logic bugs


class ScanThread(threading.Thread): 

	def __init__(self, sid, global_stats,timeout_sec): 
		self.sid = sid
		self.global_stats = global_stats
		self.global_stats.active_threads += 1
		threading.Thread.__init__(self)
		self.timeout_sec = timeout_sec
		self.global_stats.threads[sid] = time.time() 
		self.timeout_exc = SSLScanTimeoutException() 
		self.alert_exc = SSLAlertException("foo")

	def get_errno(self, e): 
		try: 
			return e.args[0]
		except: 
			return 0 # no error

	def record_failure(self, e,): 
		stats.failures += 1
		if type(e) == type(self.timeout_exc): 
			stats.failure_timeouts += 1
			return
		if type(e) == type(self.alert_exc): 
			stats.failure_ssl_alert += 1
			return

		err = self.get_errno(e) 
		if err == errno.ECONNREFUSED or err == errno.EINVAL:
			stats.failure_conn_refused += 1
		elif err == errno.EHOSTUNREACH or err == errno.ENETUNREACH: 
			stats.failure_no_route += 1
		elif err == errno.ECONNRESET: 
			stats.failure_conn_reset += 1
		elif err == -2 or err == -3 or err == -5 or err == 8: 
			stats.failure_dns += 1
		else: 	
			stats.failure_other += 1 
			print "Unknown error scanning '%s'" % self.sid 
			traceback.print_exc(file=sys.stdout)

	def run(self): 
		try: 
			fp = attempt_observation_for_service(self.sid, self.timeout_sec)
			print "Got: %s, %s" % (self.sid, fp)
			res_list.append((self.sid,fp))
		except Exception, e:
			self.record_failure(e) 

		self.global_stats.num_completed += 1
		self.global_stats.active_threads -= 1
		
		del self.global_stats.threads[self.sid]

class GlobalStats(): 

	def __init__(self): 
		self.failures = 0
		self.num_completed = 0
		self.active_threads = 0 
		self.num_started = 0 
		self.threads = {} 

		# individual failure counts
		self.failure_timeouts = 0
		self.failure_no_route = 0
		self.failure_conn_refused = 0
		self.failure_conn_reset = 0
		self.failure_dns = 0 
		self.failure_ssl_alert = 0
		self.failure_other = 0 
	
if len(sys.argv) != 5: 
  print >> sys.stderr, "ERROR: usage: <notary.config> <service_id_file> <scans-per-sec> <timeout sec> " 
  sys.exit(1)

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

if sys.argv[2] == "-": 
	f = sys.stdin
else: 
	f = open(sys.argv[2])

res_list = [] 
stats = GlobalStats()
rate = int(sys.argv[3])
timeout_sec = int(sys.argv[4]) 
start_time = time.time()
localtime = time.asctime( time.localtime(start_time) )
print "Starting scan at: %s" % localtime
print "INFO: *** Timeout = %s sec  Scans-per-second = %s" % \
    (timeout_sec, rate) 

# reading all sids was necessary with sqlite when piped with utilities/list_service_ids.py
# to prevent sqlite lockup, but is no longer necessary
all_sids = [ line.rstrip() for line in f ]

for sid_str in all_sids:  
	try:
		sid = notary_common.ObservedServer(sid_str)
		# ignore non SSL services
		if sid.service_type == sid.SSL: 
			stats.num_started += 1
			t = ScanThread(sid,stats,timeout_sec)
			t.start()

		if (stats.num_started % rate) == 0: 
			time.sleep(1)
			try: 
				for r in res_list:
					print "reporting %s, %s" % (r[0], r[1])
					notary_common.report_observation(r[0], r[1]) 
			except:
				# TODO: we should probably retry here 
				print "DB Error: Failed to write res_list of length %s" % len(res_list)
				traceback.print_exc(file=sys.stdout)
				
			res_list = [] 
			so_far = int(time.time() - start_time)
			print "%s seconds passed.  %s complete, %s failures.  %s Active threads" % \
				(so_far, stats.num_completed, 
					stats.failures, stats.active_threads)
			print "failure details: timeouts = %s, ssl-alerts = %s, no-route = %s, conn-refused = %s, conn-reset = %s, dns = %s, other = %s" % \
				(stats.failure_timeouts,
				stats.failure_ssl_alert,
				stats.failure_no_route,
				stats.failure_conn_refused,
				stats.failure_conn_reset,
				stats.failure_dns, 
				stats.failure_other)
			sys.stdout.flush()

		if stats.num_started  % 1000 == 0: 
			print "long running threads" 
			cur_time = time.time() 
			for sid in stats.threads.keys(): 
				duration = cur_time - stats.threads.get(sid,cur_time)
				if duration > 20: 
					print "'%s' has been running for %s" % (sid,duration) 
			sys.stdout.flush()

	except KeyboardInterrupt: 
		exit(1)	

if stats.active_threads > 0: 
	time.sleep(2 * timeout_sec)

duration = int(time.time() - start_time)
localtime = time.asctime( time.localtime(start_time) )
print "Ending scan at: %s" % localtime
print "Scan of %s services took %s seconds.  %s Failures" % (stats.num_started,duration, stats.failures)
exit(0) 

