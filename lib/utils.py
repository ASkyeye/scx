import random, string

def random_string(): return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(28))
def format_shellcode(ciphertext): return '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' }'