# -*- coding:utf-8 -*-

# snmp_passpersist.py - SNMP passPersist backend for Net-SNMP
# Copyleft 2010-2013 - Nicolas AGIUS <nicolas.agius@lps-it.fr>

###########################################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###########################################################################

"""
This 'snmp_passpersist' module is a python backend for snmp's "pass_persist" function.

It is critical that the python interpreter be invoked with unbuffered STDIN and
STDOUT by use of the -u switch in the shebang line.

All the methods are in the PassPersist class.
"""

import sys, time, threading, os

__all__ = [ "Error", "ErrorValues", "Type", "TypeValues", "PassPersist" ]

__author__ = "Nicolas Agius"
__license__ = "GPL"
__version__ = "1.3.0"
__email__ = "nicolas.agius@lps-it.fr"
__status__ = "Production"


class Error(object):
	"""
	SET command requests errors.
	As listed in the man snmpd.conf(5) page
	"""
	NotWritable = 'not-writable'
	WrongType = 'wrong-type'
	WrongValue = 'wrong-value'
	WrongLength = 'wrong-length'
	InconsistentValue = 'inconsistent-value'
ErrorValues = Error.__dict__.values()


class Type:
	"""
	SET command requests value types.
	As listed in the man snmpd.conf(5) page
	"""
	Integer = 'integer'
	Gauge = 'gauge'
	Counter = 'counter'
	TimeTicks = 'timeticks'
	IPAddress = 'ipaddress'
	OID = 'objectid'
	ObjectID = 'objectid'
	String = 'string'
TypeValues = Type.__dict__.values()


class ResponseError(ValueError):
	"""
	Wrong user function 
	"""

class PassPersist:
	"""
	This class present a convenient way to creare a MIB subtree and expose it to snmp via it's passpersist protocol.
	Two thread are used, one for talking with snmpd and a second that trigger the update process at a fixed interval.

	The keyword 'DUMP' has been added to the protocol for testing purpose.

	Usage example: in a file /path/to/your/script.py :

	> #!/usr/bin/python -u
	> import snmp_passpersist as snmp
	>
	> def update():
	> 	pp.add_int('0.1',123)
	>
	> pp=snmp.PassPersist(".1.3.6.1.3.53.8")
	> pp.start(update,30) # Every 30s

	With the folowing line in snmpd.conf :

	pass_persist    .1.3.6.1.3.53.8.0     /path/to/your/script.py

	"""

	@staticmethod
	def encode(string):
		"""
		Encode the given string as an OID.

		>>> import snmp_passpersist as snmp
		>>> snmp.PassPersist.encode("hello")
		'5.104.101.108.108.111'
		>>>
		"""

		result=".".join([ str(ord(s)) for s in string ])
		return  "%s." % (len(string)) + result

	def __init__(self, base_oid):
		"""
		Initialize internals structures.
		base_oid is the OID prefix used for all entry (the root of the MIB tree).
		"""

		self.data=dict()
		self.data_idx=list()
		self.pending=dict()
		self.lock=threading.RLock()
		if not base_oid.endswith("."):
			base_oid += "."
		self.base_oid=base_oid
		self.setter = dict()

		# The data structure is a dict that hold the unsorted MIB tree like this :
		# data = {
		#	'1.1': { 'type':'INTEGER', 'value':4 },
		#	'1.3.2.1':{ 'type':'STRING', 'value':'vm1' }
		#	}

	def get(self,oid):
		"""Return snmp value for the given OID."""
		try:
			self.lock.acquire()
			if oid not in self.data:
				return "NONE"
			else:
				return self.base_oid + oid + '\n' + self.data[oid]['type'] + '\n' +	str(self.data[oid]['value'])
		finally:
			self.lock.release()

	def get_next(self,oid):
		"""Return snmp value for the next OID."""
		try: # Nested try..except because of Python 2.4
			self.lock.acquire()
			try:
				# remove trailing zeroes from the oid
				while len(oid) > 0 and oid[-2:] == ".0" and oid not in self.data:
					oid = oid[:-2];
				return self.get(self.data_idx[self.data_idx.index(oid)+1])
			except ValueError:
				# Not found: try to match partial oid
				for real_oid in self.data_idx:
					if real_oid.startswith(oid):
						return self.get(real_oid)
				return "NONE" # Unknown OID
			except IndexError:
				return "NONE" # End of MIB
		finally:
			self.lock.release()

	def get_first(self):
		"""Return snmp value for the first OID."""
		try: # Nested try..except because of Python 2.4
			self.lock.acquire()
			try:
				return self.get(self.data_idx[0])
			except (IndexError, ValueError):
				return "NONE"
		finally:
			self.lock.release()

	def cut_oid(self,full_oid):
		"""
		Remove the base OID from the given string.

		>>> import snmp_passpersist as snmp
		>>> pp=snmp.PassPersist(".1.3.6.1.3.53.8")
		>>> pp.cut_oid(".1.3.6.1.3.53.8.28.12")
		'28.12'
		"""
		if not full_oid.startswith(self.base_oid.rstrip('.')):
			return None
		else:
			return full_oid[len(self.base_oid):]

	def add_oid_entry(self, oid, type, value):
		"""General function to add an oid entry to the MIB subtree."""
		self.pending[oid]={'type': str(type), 'value': str(value)}

	def add_int(self,oid,value):
		"""Short helper to add an integer value to the MIB subtree."""
		self.add_oid_entry(oid,'INTEGER',value)

	def add_str(self,oid,value):
		"""Short helper to add a string value to the MIB subtree."""
		self.add_oid_entry(oid,'STRING',value)

	def add_cnt_32bit(self,oid,value):
		"""Short helper to add a 32 bit counter value to the MIB subtree."""
		# Truncate integer to 32bits max
		self.add_oid_entry(oid,'Counter32',int(value)%4294967296)

	def add_cnt_64bit(self,oid,value):
		"""Short helper to add a 64 bit counter value to the MIB subtree."""
		# Truncate integer to 64bits max
		self.add_oid_entry(oid,'Counter64',int(value)%18446744073709551615)

	def add_gau(self,oid,value):
		"""Short helper to add a gauge value to the MIB subtree."""
		self.add_oid_entry(oid,'GAUGE',value)
		
	def add_tt(self,oid,value):	
		"""Short helper to add a timeticks value to the MIB subtree."""
		self.add_oid_entry(oid,'TIMETICKS',value)
		
	def main_passpersist(self):
		"""
		Main function that handle SNMP's pass_persist protocol, called by
		the start method.
		Direct call is unnecessary.
		"""
		line = sys.stdin.readline().strip()
		if not line:
			raise EOFError()

		if 'PING' in line:
			print "PONG"
		elif 'getnext' in line:
			oid = self.cut_oid(sys.stdin.readline().strip())
			if oid is None:
				print "NONE"
			elif oid == "":
				# Fallback to the first entry
				print self.get_first()
			else:
				print self.get_next(oid)
		elif 'get' in line:
			oid = self.cut_oid(sys.stdin.readline().strip())
			if oid is None:
				print "NONE"
			else:
				print self.get(oid)
		elif 'set' in line:
			oid = sys.stdin.readline().strip()
			typevalue = sys.stdin.readline().strip()
			self.set(oid, typevalue)
		elif 'DUMP' in line: # Just for debbuging
			from pprint import pprint
			pprint(self.data)
		else:
			print "NONE"

		sys.stdout.flush()

	def commit(self):
		"""
		Commit change made by the add_* methods.
		All previous values with no update will be lost.
		This method is automatically called by the updater thread.
		"""

		# Generate index before acquiring lock to keep locked section fast
		# Works because this thread is the only writer of self.pending
		pending_idx = sorted(self.pending.keys(), key=lambda k: tuple(int(part) for part in k.split('.')))

		# Commit new data
		try:
			self.lock.acquire()
			self.data=self.pending
			self.pending=dict()
			self.data_idx = pending_idx
		finally:
			self.lock.release()

	def main_update(self):
		"""
		Main function called by the updater thread.
		Direct call is unnecessary.
		"""
		# Renice updater thread to limit overload
		try:
			os.nice(1)
		except AttributeError as er:
			pass # os.nice is not available on windows
		time.sleep(self.refresh)

		try:
			while True:
				# We pick a timestamp to take in account the time used by update()
				timestamp=time.time()

				# Update data with user's defined function
				self.update()

				# We use this trick because we cannot use signals in a backoffice threads
				# and alarm() mess up with readline() in the main thread.
				delay=(timestamp+self.refresh)-time.time()
				if delay > 0:
					if delay > self.refresh:
						time.sleep(self.refresh)
					else:
						time.sleep(delay)

				# Commit change exactly every 'refresh' seconds, whatever update() takes long.
				# Commited values are a bit old, but for RRD, punctuals values
				# are better than fresh-but-not-time-constants values.
				self.commit()

		except Exception,e:
			self.error=e
			raise

	def get_setter(self, oid):
		"""
		Retrieve the nearest parent setter function for an OID
		"""
		if hasattr(self.setter, oid):
			return self.setter[oid]
		parents = [ poid for poid in self.setter.keys() if oid.startswith(poid) ]
		if parents:
			return self.setter[max(parents)]
		return self.default_setter
	
	def register_setter(self, oid, setter_func):
		"""
		Set reference to an user defined function for deal with set commands.
		The user function receives the OID, type (see Type class) and value
		and must return a true value on succes or one of errors in Error class
		"""
		self.setter[oid] = setter_func

	def default_setter(self, oid, _type, value):
		return Error.NotWritable

	def set(self, oid, typevalue):
		"""
		Call the default or user setter function if available 
		"""
		success = False
		type_ = typevalue.split()[0]
		value = typevalue.lstrip(type_).strip().strip('"')
		ret_value = self.get_setter(oid)(oid, type_, value)
		if ret_value:
			if ret_value in ErrorValues or ret_value == 'DONE':
				print ret_value
			elif ret_value == True:
				print 'DONE'
			elif ret_value == False:
				print Error.NotWritable
			else:
				raise RuntimeError("wrong return value: %s" % str(ret_value))
		else:	
			print Error.NotWritable

	def start(self, user_func, refresh):
		"""
		Start the SNMP's protocol handler and the updater thread
		user_func is a reference to an update function, ran every 'refresh' seconds.
		"""
		self.update=user_func
		self.refresh=refresh
		self.error=None

		# First load
		self.update()
		self.commit()

		# Start updater thread
		up = threading.Thread(None,self.main_update,"Updater")
		up.daemon = True
		up.start()

		# Main loop
		while up.isAlive(): # Do not serve data if the Updater thread has died
			try:
				self.main_passpersist()
			except:
				up._Thread__stop()
				raise

# vim: ts=4:sw=4:ai
