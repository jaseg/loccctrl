#!/usr/bin/env python

import base64
import hashlib
import serial
import time
import threading
import functools
import os
import sys
import signal
from lmap import *

import config

def log(*args):
	print(*args)
	sys.stdout.flush()

PIN_CACHE = {}

class HardwareInterface:
	def __init__(self):
		self.ser = serial.Serial(port=config.PORT, baudrate=config.BAUDRATE, timeout=10)
		self.lock = threading.Lock()
		self.set_led('green', False)
		self.set_led('red', False)
		self.set_led('yellow', False)

	def set_led(self, led, val):
		LED_MAP = {'red': b'1', 'yellow': b'2', 'green': b'0'}
		with self.lock:
			self.ser.write(b'\nl'+LED_MAP[led]+(b'1' if val else b'0')+b'\n')
			self.ser.read(1)
	
	def blink_led(self, led, duration, val=True):
		self.set_led(led, val)
		time.sleep(duration)
		self.set_led(led, not val)
	
	def open(self):
		with self.lock:
			self.ser.write(b'\no\n')
			self.ser.read(4)
	
	def flush(self):
		self.ser.flushInput();

	def try_open(self):
		if not self.lock.acquire(False):
			return False
		self.ser.write(b'\no\n')
		self.ser.read(4)
		self.lock.release()
		return True
	
	def readcmd(self):
		with self.lock:
			return self.ser.read(1)

def ldap_connect():
	ld = ldap.ldap(config.LDAP.URI)
	ld.simple_bind(config.LDAP.BINDDN, config.LDAP.BINDPW)
	return lmap.lmap(dn=config.LDAP.BASE, ldap=ld)

def pwcheck(record, pw):
	if not record.startswith('{SSHA}'):
		return record == pw
	bd = base64.b64decode(record[6:])
	hashv = bd[:20]
	salt = bd[20:]
	newhashv = hashlib.sha1(bytes(pw, 'UTF-8')+salt).digest()
	return hashv == newhashv

def populate_cache(_signum=None, _frame=None):
	log('Repopulating cache...')
	lm = ldap_connect()
	users = lm(config.LDAP.USERBASE).search(config.LDAP.ENTIRE_GROUP_FILTER)
	if len(users) > 0:
		print('Found {} allowed users, looking for keys...'.format(len(users)))
		PIN_CACHE = {u[config.LDAP.UID_FIELD]: u[config.LDAP.PIN_FIELD] for u in users if config.LDAP.PIN_FIELD in u}
	log('Repopulated cache with {} entries.'.format(len(users)))

def test_access(uid, pin):
	log('Looking up user', uid)
	try:
		lm = ldap_connect()
		users = lm(config.LDAP.USERBASE).search(config.LDAP.ACCESS_FILTER.format(uid))

		if len(users) == 0: # empty result
			print('User not found:', uid)
			if uid in PIN_CACHE:
				del PIN_CACHE[uid]
			return False

		PIN_CACHE[uid] = users[0][config.LDAP.PIN_FIELD]
	except Exception as e:
		log('LDAP error looking up ', uid, ':', str(e))
	if pwcheck(PIN_CACHE.get(uid, config.BACKUP_PIN), pin):
		return True
	return False

log('Starting up...')
hw = HardwareInterface()
hw.blink_led('red', 1.0)
hw.blink_led('green', 1.0)
hw.set_led('yellow', True)
log('Hardware interface initialized.')

# Caching logic
populate_cache()
signal.signal(signal.SIGALRM, populate_cache)
signal.setitimer(signal.ITIMER_REAL, config.LDAP.CACHE_REFRESH_IVL)

if __name__ == '__main__':
	nums = list(map(str, range(10)))
	numbuf = ''
	last_input = 0
	while True:
		try:
			# read command
			cmd = str(hw.readcmd(), 'ASCII')
			#log('CMD:', cmd, 'numbuf:', numbuf)
			hw.blink_led('yellow', 0.1, False)

			# input timeout
			now = time.time()
			if now-last_input > config.INPUT_TIMEOUT:
				numbuf = ''
			last_input = now

			# append number
			if cmd in nums:
				numbuf += cmd
			
			elif cmd in ['a', 'H'] and len(numbuf) > 4: # accept
				log('Checking access...')
				uid, pin, numbuf = numbuf[:4], numbuf[4:], ''
				if(test_access(uid, pin)):
					log('Access granted')
					hw.set_led('green', True)
					hw.open()
					hw.set_led('green', False)
					hw.flush()
				else:
					for i in range(5):
						hw.blink_led('red', 0.1) # red
						time.sleep(0.1)
					log('Access denied')
			
			elif cmd in ['c', 'h']: # cancel
				if len(numbuf) > 0:
					log('Aborted.')
					hw.blink_led('red', 1.0)
					numbuf = ''
				else:
					hw.blink_led('red', 0.1)

		except Exception as e:
			log('Error in main loop:', e)
			sys.exit(3)

