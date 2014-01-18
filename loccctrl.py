#!/usr/bin/env python

import base64
import hashlib
import serial
import time
import threading
import functools
from lmap import *

import config

PIN_CACHE = {}

class HardwareInterface:
	def __init__(self):
		self.ser = serial.Serial(port=config.PORT, baudrate=config.BAUDRATE, timeout=10)
		self.lock = threading.Lock()

	def set_led(self, led, val):
		with self.lock:
			self.ser.write(bytes([ord('\n'), ord('l'), ord(str(int(led))), ord(str(int(val))), ord('\n')]))
			self.ser.read(1)
	
	def blink_led(self, led, duration, val=True):
		self.set_led(led, val)
		time.sleep(duration)
		self.set_led(led, not val)
	
	def open(self):
		with self.lock:
			self.ser.write(b'\no\n')
			self.ser.read(4)
	
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

def test_access(uid, pin):
	print('Looking up user', uid)
	try:
		lm = ldap_connect()
		user = lm(config.LDAP.USERBASE).search(config.LDAP.ACCESS_FILTER.format(uid))[0]
		PIN_CACHE[uid] = user[config.LDAP.PINFIELD]
	except Exception as e:
		print('Invalid user/pin:', uid, '('+str(e)+')')
	if pwcheck(PIN_CACHE.get(uid, config.BACKUP_PIN), pin):
		return True
	return False

print('Starting up...')
hw = HardwareInterface()
hw.set_led(0, False) # green
hw.set_led(1, False) # red
hw.set_led(2, True) # yellow
print('Hardware interface initialized.')

nums = list(map(str, range(10)))

numbuf = ''
while True:
	cmd = str(hw.readcmd(), 'ASCII')
	#print('CMD:', cmd, 'numbuf:', numbuf)
	hw.blink_led(2, 0.1, False) # yellow
	if cmd in nums:
		numbuf += cmd
	if cmd in ['a', 'H'] and len(numbuf) > 4:
		print('Checking access...')
		uid = numbuf[:4]
		pin = numbuf[4:]
		if(test_access(uid, pin)):
			print('Access granted')
			hw.set_led(0, True) # green
			hw.open()
			hw.set_led(0, False) # green
			numbuf = ''
		else:
			for i in range(10):
				hw.blink_led(1, 0.1) # red
				time.sleep(0.1)
			print('Access denied')
			numbuf = ''
	if cmd in ['c', 'h']:
		print('Aborted.')
		hw.blink_led(1, 1.0) # red
		numbuf = ''

