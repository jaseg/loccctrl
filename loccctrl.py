#!/usr/bin/env python

import base64
import hashlib
import serial
import time
from lmap import *

import config

class HardwareInterface:
	def __init__(self):
		self.ser = serial.Serial(port=config.PORT, baudrate=config.BAUDRATE)

	def set_led(self, led, val):
		self.ser.write(bytes([ord('l'), ord(str(int(led))), ord(str(int(val))), ord('\n')]))
	
	def open(self):
		self.ser.write(b'o\n')
		self.ser.read(1)
	
	def readcmd(self):
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
	lm = ldap_connect()
	print('Looking up user', uid)
	try:
		user = lm(config.LDAP.USERBASE).search(config.LDAP.ACCESS_FILTER.format(uid))[0]
		if pwcheck(user[config.LDAP.PINFIELD], pin):
			return True
	except Exception as e:
		print('Invalid user/pin:', uid, '('+str(e)+')')
	return False

hw = HardwareInterface()

nums = list(map(str, range(10)))

numbuf = ''
while True:
	cmd = str(hw.readcmd(), 'ASCII')
	print('CMD:', cmd, 'numbuf:', numbuf)
	if cmd in nums:
		numbuf += cmd
	if cmd in ['a', 'H']:
		print('Checking access...')
		uid = numbuf[:4]
		pin = numbuf[4:]
		if(test_access(uid, pin)):
			print('Access granted')
			hw.open()
		else:
			print('Access denied')
	if cmd in ['c', 'h']:
		print('Aborted.')
		numbuf = ''

