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
import time 
import notary_common 
import threading
import errno
import Queue
import logging

from ssl_scan_sock import attempt_observation_for_service, SSLScanTimeoutException, SSLAlertException
import config
import db

# TODO: more fine-grained error accounting to distinguish different failures
# (dns lookups, conn refused, timeouts).  Particularly interesting would be
# those that fail or hang after making some progress, as they could indicate
# logic bugs

#TODO sharing global_stats in threads has potential race condition; it also breaks
#when hosts in input are not unique due to self.global_stats.threads[sid]

class ScanThread(threading.Thread):
	"""Worker thread scanning service taken from synchronized queue."""

	def __init__(self, que, global_stats,timeout_sec): 
		self.que = que
		self.global_stats = global_stats
		self.global_stats.active_threads += 1
		threading.Thread.__init__(self)
		self.timeout_sec = timeout_sec
		self.timeout_exc = SSLScanTimeoutException() 
		self.alert_exc = SSLAlertException("foo")

	def get_errno(self, e): 
		try: 
			return e.args[0]
		except: 
			return 0 # no error

	def record_failure(self, e, sid):
		logging.debug("Failed to get sid %s: %s" % (sid, e))
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

	def run(self):
		while True:
			sid = self.que.get()
			
			try: 
				fp = attempt_observation_for_service(sid, self.timeout_sec)
				result_queue.put((sid,fp))
			except Exception, e:
				self.record_failure(e, sid)
				
			self.que.task_done()

class StorageThread(threading.Thread):
	"""Thread storing scanned observations into database."""
	
	def __init__(self, result_queue):
		self.result_queue = result_queue
		threading.Thread.__init__(self)
	
	def run(self):
		while True:
			scan_result = self.result_queue.get()
			try:
				(sid, fp) = scan_result
				notary_common.report_observation(sid, fp)
				logging.debug("Storing sid %s" % sid)
			except Exception:
				logging.exception("Failed to store result %s")
			
			self.result_queue.task_done()
		
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
	print >> sys.stderr, "ERROR: usage: <notary.config> <service_id_file> <thread_count> <timeout sec> " 
	sys.exit(1)

config.config_initialize(sys.argv[1])
db.db_initialize(config.Config)

logging.basicConfig(filename=config.Config.scanner_log, level=config.Config.scanner_loglevel,
	format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")


if sys.argv[2] == "-": 
	f = sys.stdin
else: 
	f = open(sys.argv[2])

#Limit queue sizes so that the script won't consume too much memory by
#reading all of the sids to scan into memory at once. Helps in case
#the number of sids is huge (like million or more).
QUEUE_SIZE = 20000

result_queue = Queue.Queue(maxsize=QUEUE_SIZE)


stats = GlobalStats()
thread_count = int(sys.argv[3])
timeout_sec = int(sys.argv[4]) 
start_time = time.time()
localtime = time.asctime( time.localtime(start_time) )
logging.info("Starting scan at: %s" % localtime)
logging.info("Timeout = %s sec  Thread count = %s" % (timeout_sec, thread_count) )

que = Queue.Queue(maxsize=QUEUE_SIZE)

for i in range(thread_count):
	t = ScanThread(que, stats, timeout_sec)
	t.setDaemon(True)
	t.start()

storage_thread = StorageThread(result_queue)
storage_thread.setDaemon(True)
storage_thread.start()

sids_count = 0
for line in f:
	try:
		sids_count += 1
		sid_str = line.rstrip()
		sid = notary_common.ObservedServer(sid_str)
		que.put(sid)
	except ValueError:
		logging.debug("Skipping sid %s: malformed")
		
try:
	logging.debug("Wating for scans to finish")
	que.join()
	logging.debug("Scans finished")
	result_queue.join()
	logging.debug("Scans stored")

except KeyboardInterrupt: 
	exit(1)	

duration = int(time.time() - start_time)
localtime = time.asctime( time.localtime(start_time) )
logging.info("Ending scan at: %s" % localtime)
logging.info("Scan of %s services took %s seconds.  %s Failures" % (sids_count,duration, stats.failures))
exit(0) 

