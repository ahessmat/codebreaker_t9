from Crypto.Cipher import AES
import Crypto.Cipher.AES
from binascii import hexlify, unhexlify

import os
import subprocess




def solve(cracked):
	testbyte = b''
	with open("id.pdf.enc","rb") as f:
		testbyte = f.read()
	key = unhexlify(cracked)
	iv = unhexlify('7f74c97196b7e99a0a40771c4f51cc61') #This value was given as part of the encrypted file
	cipher = AES.new(key,AES.MODE_CBC,iv) #This cipher information was solved in previous NSA codebreaker challenge problems
	decipher = cipher.decrypt(testbyte)
	if b'PDF' in decipher:
		print(decipher[:20])
	with open("decrypted.pdf","wb") as g:
		g.write(decipher)
