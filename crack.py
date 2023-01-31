import time
import multiprocessing as mp
from Crypto.Cipher import AES
from binascii import unhexlify
from functools import partial
from unransom import solve

#Define some pretty colors for output text
IBlack="\033[0;90m"       # Black
IRed="\033[0;91m"         # Red
IGreen="\033[0;92m"       # Green
IYellow="\033[0;93m"      # Yellow
IBlue="\033[0;94m"        # Blue
IPurple="\033[0;95m"      # Purple
ICyan="\033[0;96m"        # Cyan
IWhite="\033[0;97m"       # White


#Helper method
#Used to convert an integer to a hex digit in string format
#Invoked by runme() for assembling 
def getval(strval):
	try:
		x = hex(strval)[2]
	except:
		print(f"[-] ERROR: could not process value {strval}")
	return x

#These are the encrypted bytes of the target ransomware file
hexdata = b''
with open("id.pdf.enc","rb") as f:
  hexdata = f.read()

#This is the function that each core will run to decrypt id.pdf.enc
def runme(event,lst):
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
												print(IGreen + "[+] FOUND IT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
												et = time.time()
												elapsed_time = et - st
												print('Execution time:', elapsed_time, 'seconds')
												print(f"TID:{tid} KEY:{raw_key} PRE-KEY:{test}")
												event.set()
												print(IBlue + "[*] Writing decrypted file")
												solve(test)
												return
										
					if event.is_set():
						return
					else:
						print(IRed + f'{tid}: {raw_key}')
						continue
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

# 406ec0d90 <-- Already solved it, so you can plug this value in instead for expediency
print(IBlue + "[*] Running!")
print(IBlue + "[*] Decryption key is in the form ********-aaa1-11ec-beec-000c294a")
listofvals = [ breakup("000000000"),
		breakup("400000000"),
		breakup("800000000"),
		breakup("c00000000")]

pool = mp.Pool(4)

#I needed an event manager to capture when one of the child processes successfully found a key
#This required passing an event from mp.manager.event()
#I had to subsequently alter the code so that mp.map() could accept multiple arguments
with mp.Manager() as manager:
	event = manager.Event()
	func = partial(runme,event)
	pool.map(func,listofvals)
	print(IYellow + "[-] Result found, terminating...")
pool.close()
pool.join()

											
et = time.time()

elapsed_time = et - st
print('FINAL Execution time:', elapsed_time, 'seconds')
