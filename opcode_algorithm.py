def opcode_fingerprinting(opcode,N=100):
    #opcode is a list of different opcodes
    if N>=0:
        OCSet=set()
        CR=opcode[0]
        SR=opcode[1]
        i=2
        while i!= N & i< len(opcode):
            if opcode[i] in [CR, SR] and len(OCSet)>=4:
                return False
            OCSet.add(opcode[i])
            i += 1
        print(OCSet)
        return (i ==N) & (4 <= len(OCSet)<= 10)