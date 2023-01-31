from Crypto.Cipher import AES
import Crypto.Cipher.AES
from binascii import hexlify, unhexlify

import os
import subprocess
'''
hexdata = b''
#with open("t.enc","rb") as f:
with open("manifesto.pdf","rb") as f:
	hexdata = f.read()
'''  
#print(hexdata)
#print()
'''
testkey = "12345678-fe26-11ec-9ab1-204e21e7"

key = os.popen(f"echo -n {testkey} | ./busybox xxd -p | ./busybox head -c 32").read()
key = '33353666313332322d666532362d3131'
os.system(f"./openssl enc -e -aes-128-cbc -K {key} -iv 7f74c97196b7e99a0a40771c4f51cc61 -in manifesto.pdf > test.pdf.enc")
#baseline = os.popen(f"./openssl enc -d -aes-128-cbc -K {key} -iv 7f74c97196b7e99a0a40771c4f51cc61 -in id.pdf.enc").read()

#print(type(baseline))

testbyte = b''
with open("test.pdf.enc","rb") as f:
	testbyte = f.read()
'''
testbyte = b''
with open("id.pdf.enc","rb") as f:
	testbyte = f.read()

#key = '61633166666237642d616161652d3131'	#ac1ffb7d-aaae
#key = '36396666353439302d616161332d3131'	#69ff5490-aaa3	
#key = '32346266363831332d616161372d3131'	#24bf6813-aaa7

key = '34303665633064392d616161312d3131'	#406ec0d9-aaa1
key2 = unhexlify(key)
iv = unhexlify('7f74c97196b7e99a0a40771c4f51cc61')
cipher = AES.new(key2,AES.MODE_CBC,iv)
decipher = cipher.decrypt(testbyte)
if b'PDF' in decipher:
	print(decipher[:20])

with open("imp3.pdf", "wb") as f:
	f.write(decipher)
