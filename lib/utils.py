import random, string

def random_string(max=28): return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(random.randint(14,max)))
def format_shellcode(ciphertext): return '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' }'