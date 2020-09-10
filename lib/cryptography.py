from lib import utils
import hashlib, binascii

def get_hash(): return hashlib.md5(utils.random_string(60).encode('utf-8')).hexdigest()	

def xor(data, key):
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(current ^ ord(current_key))
	return output_str
