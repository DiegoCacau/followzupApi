import base64
import os
import crypto
from lxml import objectify
import pycurl
from io import BytesIO


class fzup_: #idchannel#
	fzup_channel  = "" #idchannel#
	fzup_lastseq  = 0
	fzup_pubkey   = ""
	fzup_pubkey64 = "" #key64#

	def __init__(self):
		self.fzup_pubkey = base64.b64decode(self.fzup_pubkey64).decode('ascii')
		


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
				"<sub>" + fzup_param["FZUP_SUBSCODE"] + "</sub>"

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
			
			fzup_key1 = crypto.openssl_random_pseudo_bytes()
			fzup_frame2 = crypto.encrypt_(fzup_frame1, fzup_key1, iv)
			fzup_key2 = crypto.openssl_public_encrypt(fzup_key1, self.fzup_pubkey)
			fzup_frame3 = base64.b64encode(fzup_frame2)
			fzup_key3 = base64.b64encode(fzup_key2)
			
			bound = crypto.openssl_random_pseudo_bytes(length=16)
			
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
			fzup_retframe3 = crypto.decrypt_(fzup_retframe2,fzup_key1,iv)			
			fzup_retframe4 = objectify.fromstring(fzup_retframe3.encode())

			if (fzup_retcode == "6101" ): 
				self.fzup_lastseq = fzup_retframe4.seq

			if (fzup_retcode != "6101"):
				break

		return ( fzup_retcode, self.fzup_lastseq, fzup_retframe3)	

	
