# SCX

## Help
```
usage: shellcode-builder.py [-h] -b  [-k] [-n] [--x64] [--sign] [--strip]

Build XOR'd shellcode executables.

optional arguments:
  -h, --help      show this help message and exit
  -b , --binary   Raw file to encrypt
  -k , --key      Key to encrypt with (random by default)
  -n , --name     Name of executable (random by xor_beacon_*.exe)
  --x64           Set compiler to x64
  --sign          Sign with TCPView's Certificate
  --strip         Strip Binary
```

## Sample
```
  ██████  ▄████▄  ▒██   ██▒
▒██    ▒ ▒██▀ ▀█  ▒▒ █ █ ▒░
░ ▓██▄   ▒▓█    ▄ ░░  █   ░
  ▒   ██▒▒▓▓▄ ▄██▒ ░ █ █ ▒ 
▒██████▒▒▒ ▓███▀ ░▒██▒ ▒██▒ Author: mez0
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░▒▒ ░ ░▓ ░ GitHub: https://github.com/mez-0
░ ░▒  ░ ░  ░  ▒   ░░   ░▒ ░
░  ░  ░  ░         ░    ░  
      ░  ░ ░       ░    ░  
         ░                 

09/09/20, 21:01:51 ==> Architecture: x64
09/09/20, 21:01:51 ==> Key: 2483c6ed59fc549b0db9571c09193edb
09/09/20, 21:01:51 ==> Compiling with: x86_64-w64-mingw32-gcc ./result/xor_beacon_x64.c -o ./result/xor_beacon_x64.exe

09/09/20, 21:01:52 ==> Compiled: ./result/xor_beacon_x64.exe
09/09/20, 21:01:52 ==> Stripped: ./result/xor_beacon_x64.exe
09/09/20, 21:01:52 ==> Signed: ./result/xor_beacon_signed_x64.exe
```