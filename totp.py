#!/usr/bin/python
import pyotp
import json

import os, random, struct, sys, hashlib
from Crypto.Cipher import AES

import getpass

import subprocess

def getClipboardData():
 p = subprocess.Popen(['pbpaste'], stdout=subprocess.PIPE)
 retcode = p.wait()
 data = p.stdout.read()
 return data

def setClipboardData(data):
 p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
 p.stdin.write(data)
 p.stdin.close()
 retcode = p.wait()

def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
	""" Encrypts a file using AES (CBC mode) with the
		given key.

		key:
			The encryption key - a string that must be
			either 16, 24 or 32 bytes long. Longer keys
			are more secure.

		in_filename:
			Name of the input file

		out_filename:
			If None, '<in_filename>.enc' will be used.

		chunksize:
			Sets the size of the chunk which the function
			uses to read and encrypt the file. Larger chunk
			sizes can be faster for some files and machines.
			chunksize must be divisible by 16.
	"""
	if not out_filename:
		out_filename = in_filename + '.enc'

	iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
	encryptor = AES.new(key, AES.MODE_CBC, iv)
	filesize = os.path.getsize(in_filename)

	with open(in_filename, 'rb') as infile:
		with open(out_filename, 'wb') as outfile:
			outfile.write(struct.pack('<Q', filesize))
			outfile.write(iv)

			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += ' ' * (16 - len(chunk) % 16)

				outfile.write(encryptor.encrypt(chunk))
				

def decrypt_file(key, in_filename):
	""" Decrypts a file using AES (CBC mode) with the
		given key. Parameters are similar to encrypt_file,
		with one difference: out_filename, if not supplied
		will be in_filename without its last extension
		(i.e. if in_filename is 'aaa.zip.enc' then
		out_filename will be 'aaa.zip')
	"""

	with open(in_filename, 'rb') as infile:
		origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
		iv = infile.read(16)
		decryptor = AES.new(key, AES.MODE_CBC, iv)
		return decryptor.decrypt(infile.read())


def getKey(verify=False):
		fail = True
		while fail:
			pswd = getpass.getpass('Passphrase:')
			if verify:
				pswd2 = getpass.getpass('Repeat:')
				if pswd != pswd2:
					print "Passphrase mismatch, try again!"
				else:
					fail = False
			else:
				fail = False
		return hashlib.sha256(pswd).digest()

class _Getch:
    """Gets a single character from standard input.  Does not echo to the
screen."""
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            self.impl = _GetchUnix()

    def __call__(self): return self.impl()


class _GetchUnix:
    def __init__(self):
        import tty, sys

    def __call__(self):
        import sys, tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


class _GetchWindows:
    def __init__(self):
        import msvcrt

    def __call__(self):
        import msvcrt
        return msvcrt.getch()

getch = _Getch()
if sys.argv[1] == 'list':
	in_filename = sys.argv[2] if len(sys.argv) > 2 else "totp.json.enc"
	fail = True
	while fail:
		try:
			keys = json.loads(decrypt_file(getKey(), in_filename))
		except:
			print "Decryption failed, try again!"
		else:
			fail = False
	for itemnum,item in enumerate(keys):
		print "[%d] %s" % (itemnum+1,item['keyname'])
	chosen = False
	while not chosen:
		try:
			if len(keys) < 10:
				print("Choose a key:"),
				idx = int(getch())
				print idx
			else:
				idx = int(raw_input("Choose a key: "))
		except ValueError:
			print "Try again."

		try:
			chosen = keys[idx-1]
		except IndexError:
			print "Try again."
	key = str(pyotp.TOTP(chosen['key']).now()).rjust(6,'0')
	print "TOTP Key for %s: %s" % (chosen['keyname'], key)
	print("Copy to clipboard? (y/n):"),
	response = getch()
	print response
	if response == "y":
		setClipboardData(str(key))
		print "Successfuly copied to clipboard."
	else:
		print "Ok, bye!"


if sys.argv[1] == 'encrypt':
	in_filename = sys.argv[2]
	out_filename = sys.argv[3] if len(sys.argv) > 3 else "totp.json.enc"
	encrypt_file(getKey(True), in_filename, out_filename)


if sys.argv[1] == 'decrypt':
	in_filename = sys.argv[2]
	out_filename = sys.argv[3] if len(sys.argv) > 3 else None
	decrypted = decrypt_file(getKey(), in_filename)
	if out_filename:
		with open(out_filename, 'wb') as outfile:
			outfile.write(decrypted)
		print "Successfuly decrypted to: %s" % out_filename 
	else:
		print decrypted

