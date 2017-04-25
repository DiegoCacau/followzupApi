import base64
import os
from lxml import objectify
import pycurl
from io import BytesIO
from Crypto.Cipher import AES, PKCS1_v1_5 
from Crypto.PublicKey import RSA
import sys
import subprocess


class fzup_:
	fzup_channel  = ""
	fzup_lastseq  = 0
	fzup_pubkey   = ""
	fzup_pubkey64 = ""

	def __init__(self):
		self.fzup_pubkey = base64.b64decode(self.fzup_pubkey64).decode('ascii')
		
	'''
		Because of the lack of a Python function to decrypt data using RSA public
		keys, it was necessary to install a PHP method to perform this function. 
		To do this, the PHP OpenSSL extention must be enabled to be called by
		the "decrypt" method available in this code.
	'''	
	def decrypt(self,fzup_encrypt64):
		code = '''
				<?php
				function decrypt () {
				    
				    $pubKey="'''+self.fzup_pubkey64+'''";
				    $fzup_encrypt64 = "'''+fzup_encrypt64+'''";

				    $fzup_pubkey = base64_decode($pubKey);

				    $fzup_encrypt = base64_decode($fzup_encrypt64);
				    
				    openssl_public_decrypt($fzup_encrypt, $fzup_decrypt, $fzup_pubkey);
				    
				    echo $fzup_decrypt;

				}

				return decrypt();
				?>
				'''
		res = self.php(code)
		
		return(res[0].decode("utf-8").strip())

	def Message_padding(self,message):
		Message_length = len(message)

		remainder = Message_length%16

		if (remainder) !=0:
			Padding_length = 16-remainder
			message = message+" "*Padding_length
 		return message

	def encrypt_(self,text, input_key, input_iv):
		aes = AES.new(input_key, AES.MODE_CBC, input_iv)
		cipher_text = ''
		cipher_text = aes.encrypt(self.Message_padding(text))

		return cipher_text


	def decrypt_(self,enc, key,IV):
		decobj = AES.new(key, AES.MODE_CBC, IV)
		data = (decobj.decrypt((enc)))
		return (str((data).decode()).strip("\x00"))


	def openssl_public_encrypt(self,message,key):
		k = key
		key1 = RSA.importKey(key)
		pkcs1CipherTmp = PKCS1_v1_5.new(key1)
		encryptedString = pkcs1CipherTmp.encrypt(message.encode())

		return encryptedString  


	  	

	def openssl_random_pseudo_bytes(self,length=24, charset="abcdefghijklmnopqrstuvwxyz0123456789"):
		random_bytes = os.urandom(length)

		len_charset = len(charset)
		if sys.version_info[0] >= 3:
			indices = [int(len_charset * (ord(chr(byte)) / 256.0))  for byte in random_bytes]
			return  "".join([charset[index] for index in indices])  
		else:   
			indices = [int(len_charset * (ord(byte) / 256.0))  for byte in random_bytes]
			return  "".join([charset[index] for index in indices])	



	def php(self,code):
		# open process
		p = subprocess.Popen(['php'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

		# read output
		o = p.communicate(code.encode())

		# kill process
		try:
			os.kill(p.pid, signal.SIGTERM)
		except:
			pass

		return o	
		

	def submit(self,fzup_tab):
		fzup_param={}

		fzup_param["FZUP_COMMAND"]  = ""
		fzup_param["FZUP_LASTSEQ"]  = 0
		fzup_param["FZUP_USER"]     = ""
		fzup_param["FZUP_SUBSCODE"] = "" 
		fzup_param["FZUP_HOURS"]    = 0
		fzup_param["FZUP_MSGTEXT"]  = ""
		fzup_param["FZUP_MSGURL"]   = ""	

		fzup_xml = ""	

		for i in range(len(fzup_tab)):
			fzup_token = fzup_tab[i].split("=",2)

			if(fzup_token[0].strip() == "FZUP_COMMAND"):
				fzup_param["FZUP_COMMAND"] = fzup_token[1].strip()
			elif(fzup_token[0].strip() == "FZUP_LASTSEQ"):
				fzup_param["FZUP_LASTSEQ"] = fzup_token[1].strip()
			elif(fzup_token[0].strip() == "FZUP_USER"):
				fzup_param["FZUP_USER"] = fzup_token[1].strip()	
			elif(fzup_token[0].strip() == "FZUP_SUBSCODE"):
				fzup_param["FZUP_SUBSCODE"] = fzup_token[1].strip()	
			elif(fzup_token[0].strip() == "FZUP_HOURS"):
				fzup_param["FZUP_HOURS"] = fzup_token[1].strip()	
			elif(fzup_token[0].strip() == "FZUP_MSGTEXT"):
				fzup_param["FZUP_MSGTEXT"] = fzup_token[1].strip()	
			elif(fzup_token[0].strip() == "FZUP_MSGURL"):
				fzup_param["FZUP_MSGURL"] = fzup_token[1].strip()	
								

		fzup_param["FZUP_MSGTEXT"] = base64.b64encode(fzup_param["FZUP_MSGTEXT"].encode('utf-8'))#.decode("utf-8")
		
		if len(fzup_param["FZUP_MSGURL"]) > 1:
			fzup_param["FZUP_MSGURL"]  = base64.b64encode(fzup_param["FZUP_MSGURL"].encode('utf-8')).decode('ascii')#.decode("utf-8")
		else:
			fzup_param["FZUP_MSGURL"] = ""	
		

		if(fzup_param["FZUP_COMMAND"] == "chck"):
			fzup_xml = "<usr>" + fzup_param["FZUP_USER"] + "</usr>" + \
				"<sub>" + str(fzup_param["FZUP_SUBSCODE"]) + "</sub>"

		elif (fzup_param["FZUP_COMMAND"] == "smsg"):
			fzup_xml = "<usr>" + fzup_param["FZUP_USER"] + "</usr>" + \
				"<hrs>" + str(fzup_param["FZUP_HOURS"]) + "</hrs>"  + \
				"<msg>" + fzup_param["FZUP_MSGTEXT"].decode('ascii') + "</msg>" + \
				"<url>" + fzup_param["FZUP_MSGURL"]  + "</url>"

		else:
			ret = []
			ret.append("6103")
			ret.append(self.fzup_lastseq)
			ret.append("<" +'?xml version="1.0" encoding="utf-8"?' + "><followzup></followzup>" )
			return ret		

		
		if (int(fzup_param["FZUP_LASTSEQ"]) > 0):
			self.fzup_lastseq = int(fzup_param["FZUP_LASTSEQ"])

		while True:
			self.fzup_lastseq = self.fzup_lastseq + 1
			fzup_frame1 = """<""" + """?xml version="1.0" encoding="utf-8"?"""+ """><followzup>"""
			fzup_frame1 = fzup_frame1 + """<com>"""  + fzup_param["FZUP_COMMAND"] + """</com>"""
			fzup_frame1 = fzup_frame1 + """<seq>""" + str(self.fzup_lastseq) + """</seq>"""
			fzup_frame1 = fzup_frame1 + fzup_xml + """</followzup>"""
			
			iv = chr(0)*16
			
			fzup_key1 = self.openssl_random_pseudo_bytes()
			fzup_frame2 = self.encrypt_(fzup_frame1, fzup_key1, iv)
			fzup_key2 = self.openssl_public_encrypt(fzup_key1, self.fzup_pubkey)
			fzup_frame3 = base64.b64encode(fzup_frame2)
			fzup_key3 = base64.b64encode(fzup_key2)
			
			bound = self.openssl_random_pseudo_bytes(length=16)
			
			url = "http://www.followzup.com/wschannel"

			boundary = "--------------------------"+bound
			end = "\r\n"
			agent = "wschannel: " + self.fzup_channel
			data=boundary+end+'Content-Disposition: form-data; name="id"'+end+end+self.fzup_channel+ \
				end+boundary+end+'Content-Disposition: form-data; name="key"'+end+end+fzup_key3.decode('ascii')+end+ \
				boundary+end+'Content-Disposition: form-data; name="frame"'+end+end+fzup_frame3.decode('ascii')+end+boundary+"--"+end


			

			c = pycurl.Curl()
			c.setopt(pycurl.URL, url)
			c.setopt(pycurl.USERAGENT, agent)
			c.setopt(pycurl.HTTPHEADER, ["Content-Type:multipart/form-data; boundary=------------------------"+bound,"Expect: 100-continue"])
			c.setopt(pycurl.POST, 1)
			c.setopt(pycurl.POSTFIELDS, data)
			fout = BytesIO()
			c.setopt(pycurl.WRITEDATA, fout)
			c.perform()
			response_data = fout.getvalue()
			
			fzup_respxml = objectify.fromstring(response_data)
			fzup_retcode = fzup_respxml.retcode.text
			fzup_retframe1 = fzup_respxml.retframe.text
			
			
			if fzup_retframe1 == None:
				fzup_retframe1 = ""
			
			fzup_retframe2 = base64.b64decode(fzup_retframe1.encode())
			fzup_retframe3 = self.decrypt_(fzup_retframe2,fzup_key1,iv)
			
			if len(fzup_retframe3)>0:			
				fzup_retframe4 = objectify.fromstring(fzup_retframe3.encode())

			if (fzup_retcode == "6101" ): 
				self.fzup_lastseq = fzup_retframe4.seq

			if (fzup_retcode != "6101"):
				break

		return ( fzup_retcode, self.fzup_lastseq, fzup_retframe3)	

	
