import time
import multiprocessing as mp
from Crypto.Cipher import AES
from binascii import unhexlify

#Helper method
#Used to convert an integer to a hex digit in string format
#Invoked by runme() for assembling 
def getval(strval):
	try:
		x = hex(strval)[2]
	except:
		print(f"[-] ERROR: could not process value {strval}")
	return x

#These are the encrypted bytes
hexdata = b''
with open("id.pdf.enc","rb") as f:
  hexdata = f.read()

#This is the function that each core will run to decrypt id.pdf.enc
def runme(lst):
	#Break up each digit
	start,q,w,e,r,t,y,u,v = lst
	#Create a thread ID to track the work of each running process
	tid = "last0x" + getval(start) + "-" + getval(start+3)
	test = b''
	for a in range(start,start+3):
		for b in range(q,16):
			for c in range(w,16):
				for d in range(e,16):
					for e2 in range(r,16):
						for f in range(t,16):
							for g in range(y,16):
								for h in range(u,16):
									#for i in range(v,16):
										#Get a representation of the currently tested key for console output
										raw_key = getval(a)
										raw_key += getval(b)
										raw_key += getval(c)
										raw_key += getval(d)
										raw_key += getval(e2)
										raw_key += getval(f)
										raw_key += getval(g)
										raw_key += getval(h)
										rk = raw_key

										# Coding up process to bypass busybox OS call
										test = hex(ord(getval(a)))[2:]
										test += hex(ord(getval(b)))[2:]
										test += hex(ord(getval(c)))[2:]
										test += hex(ord(getval(d)))[2:]
										test += hex(ord(getval(e2)))[2:]
										test += hex(ord(getval(f)))[2:]
										test += hex(ord(getval(g)))[2:]
										test += hex(ord(getval(h)))[2:]
										test += '2d61616131'	#	...-aaa1...
										test += '2d3131'	#	...-11

										# Decrypt with given test key
										key2 = unhexlify(test)
										iv = unhexlify('7f74c97196b7e99a0a40771c4f51cc61')
										cipher = AES.new(key2,AES.MODE_CBC,iv)

										decipher = cipher.decrypt(hexdata)

										# Check if decrypted output is what we're looking for
										if b'%PDF' in decipher[:5]:
												print("[+] FOUND IT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
												et = time.time()
												elapsed_time = et - st
												print('Execution time:', elapsed_time, 'seconds')
												print(f"TID:{tid} KEY:{raw_key} PRE-KEY:{test}")
										continue
					print(f'{tid}: {raw_key}')
	print(f'[-] {tid} FINISHED without finding result')




st = time.time()

#Helper method; used to breakup a string of hex values into a list of integers
#This was useful when I had to pause testing for whatever reason and later resume
#Arbitrary values could be written to each process
def breakup(a):
	y = [*a]
	for i,e in enumerate(y):
		y[i] = (int(e,base=16))
	return y

listofvals = [ breakup("000000000"),
		breakup("400000000"),
		breakup("800000000"),
		breakup("c00000000")]
num_workers = mp.cpu_count()
pool = mp.Pool(4)
pool.map(runme,listofvals)

											
et = time.time()

elapsed_time = et - st
print('FINAL Execution time:', elapsed_time, 'seconds')
