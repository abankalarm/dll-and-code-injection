#abusing ads 

#To use an alternate data stream on a file, we’ll need to do nothing more
#than append a colon and a filename to an existing file, like so:
#reverser.exe:vncdll.dll

import sys

#read in the dll
fd = open(sys.argv[1], "rb")
dll_contents = fd.read()
fd.close()

print("[+]file size is ", len(dll_contents))

#now write this to ads
fd = open("%s:%s" %(sys.argv[2], sys.argv[1]), "wb")
fd.write( dll_contents)
fd.close()
