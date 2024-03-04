def opcode_fingerprinting(opcode,N):
    #opcode is a list of different opcodes
    if N>=0:
        OCSet=[]
        CR=opcode[0]
        SR=opcode[1]
        i=2
        while i!= N & i< len(opcode):
            if opcode[i] in CR and opcode[i] in SR and len(OCSet)>=4:
                return False
            OCSet.append(opcode[i])
            i += 1
        return (i ==N) & (4 <= len(OCSet)<= 10)