# This file is revised based on code in https://www.capstone-engine.org/lang_python.html

from capstone import *
from capstone.arm import *

file_name = "code.bin" 		    # the name of the .bin file to be dissambled
base = 0x8000			    # base address
text_offset = 0xf4                  # the offset of the .text section in .bin

# Read binaries from .bin file
fr = open(file_name, 'rb')
CODE = fr.read()
fr.close()

CODE = CODE[text_offset:]
print(CODE)


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_V8)	# Initialize Cs class with the hardware architechture and instruction mode 
md.detail = True   # Generate more details for dissambled instructions

# Dissamble
for i in md.disasm(CODE, base + text_offset):
    if i.id == ARM_INS_STR:
	    print("%x %s:\t%s\t%s" %(i.address, i.bytes, i.mnemonic, i.op_str))