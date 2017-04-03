import base64
from Crypto.Cipher import AES, PKCS1_v1_5 
from Crypto.PublicKey import RSA
import os
import sys


def Message_padding(message):
    Message_length = len(message)
    
    remainder = Message_length%16
    
    if (remainder) !=0:
        Padding_length = 16-remainder
        message = message+" "*Padding_length
        
    return message

def encrypt_(text, input_key, input_iv):
    aes = AES.new(input_key, AES.MODE_CBC, input_iv)
    cipher_text = ''
    cipher_text = aes.encrypt(Message_padding(text))

    return cipher_text


def decrypt_(enc, key,IV):
    decobj = AES.new(key, AES.MODE_CBC, IV)
    data = (decobj.decrypt((enc)))
    return (str((data).decode()).strip("\x00"))

def openssl_public_decrypt(message,key):

	if type(key) == str:
		key = key.encode()
	key1 = RSA.importKey(key)
	if type(message) == str:
		message = message.encode()

	pkcs1CipherTmp = PKCS1_v1_5.new(key1)
	decryptedString = pkcs1CipherTmp.decrypt((message))

	return decryptedString

def openssl_public_encrypt(message,key):

	k = key
	key1 = RSA.importKey(key)
	pkcs1CipherTmp = PKCS1_v1_5.new(key1)
	encryptedString = pkcs1CipherTmp.encrypt(message.encode())

	return encryptedString  


  	

def openssl_random_pseudo_bytes(length=24, charset="abcdefghijklmnopqrstuvwxyz0123456789"):
	random_bytes = os.urandom(length)

	len_charset = len(charset)
	if sys.version_info[0] >= 3:
		indices = [int(len_charset * (ord(chr(byte)) / 256.0))  for byte in random_bytes]
		return  "".join([charset[index] for index in indices])  
	else:   
		indices = [int(len_charset * (ord(byte) / 256.0))  for byte in random_bytes]
		return  "".join([charset[index] for index in indices])	
