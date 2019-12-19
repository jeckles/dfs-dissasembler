import sys
from bfdpie import *
from capstone import *
from capstone.x86 import *
import queue

# This function is used to determine if an instruction is associated with
def isElem(d, tar):
    for k in d.keys():
        if int(k) == tar:
            return d[k]
    return False


def isMem(keys, tar):
    for k in keys:
        if int(k) == tar:
            return True
    return False

# control flow
def isCFlow(groups):
    if len(groups) > 0:
        for g in groups:
            if (g == CS_GRP_JUMP or g == CS_GRP_CALL or CS_GRP_RET or CS_GRP_IRET):
                return True
    return False

def isUnconditionalCSFlow(ins):
    return (ins.id == X86_INS_JMP or ins.id == X86_INS_LJMP or ins.id == X86_INS_RET or ins.id == X86_INS_RETF or ins.id == X86_INS_RETFQ) 



# This function is used to get the immediate target operand of the control
# flow instruction passed in. 
def insTarget(ins):
    # Get the operands of the instruction
    if isCFlow(ins.groups):
        if len(ins.operands) > 0:
            for op in ins.operands:
                # We only want the immediate control flow targets
                if (op.type == X86_OP_IMM):
                    # Return the immediate control flow target
                    return op.value.imm
    # If no immediate control flow target, return 0
    return 0

def main():
    # Check that a binary is input
    if len(sys.argv) < 2:
        sys.exit("No binary to disassemble.")

    # Load the binary passed in as a Binary
    bin = Binary(sys.argv[1])

    # Need to disassemble each executable section
    for index, sec in bin.sections.iteritems():
        if sec.flags & bfdpie.SEC_CODE:
            disasm(bin, sec)

    
def disasm(bin, to_disasm):
    stack = []
    seen = {}

    # Next, open a Capstone instance 
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    # We want to be enable detailed disassembly mode 
    md.detail = True

    #text_addr = bin.section['.text'].vma

    # Get the start address, the vma field of the Binary 
    s_addr = to_disasm.vma
    # Add the addr to the queue
    stack.append(s_addr)
    # Add start address to the seen dictionary 
    seen[s_addr] = False
    # Grab the text section of the binary

    # Contents as bytes
    contents_b = bytearray(to_disasm.contents)

    # Now, the main loop in the disasm function
    while(len(stack) != 0):
        # Grab the value at the top of the stack
        addr = stack.pop()

        # This is the byte offset used to process exactly where we want 
        # in the contents. 
        offset = addr - s_addr
        # Grab a slice of the contents based on the offset
        contents_final = contents_b[offset:]
        
        # Only want to process if the address has not been visited yet
        if seen[addr] == False:
            # Mark address to be processed as seen
            seen[addr] = True
            # Loop to retrieve information about each instruction
            # May need to add support for Halt instructions and
            # unconditional control flow instructions
            for ins in md.disasm(to_disasm.contents, addr):
                if (ins.id == X86_INS_INVALID) or (ins.size == 0):
                    break
                # Add instruction address to the seen list
                seen[int(ins.address)] = True 
                # Print the instruction
                print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
                # Now, we need to check if the instruction is a control
                # flow instruction.
                if isCFlow(ins.groups) == True:
                    # Once we know that an instruction is a control flow instruction, we will want to extract the target address
                    target = insTarget(ins)
                    # If the target has been seen already, we don't 
                    # want to add it to the stack for processing. If it 
                    # hasnt been seen, add it to the stack. 
                    if target != 0:
                        if isMem(seen.keys(), target) == False:
                            if target < to_disasm.size:
                                print("-> new target 0x%x" %(target))
                                stack.append(target)
                                seen[target] = False
                        else:
                            if seen[target] == False:
                                if target in stack == False:
                                    if target < to_disasm.size:
                                            print("-> new target 0x%x" %(target))
                                            stack.append(target)

                    if isUnconditionalCSFlow(ins):
                        break
                if ins.id == X86_INS_HLT:
                    break

if __name__ == "__main__":
    main()

