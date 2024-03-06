def opcode_fingerprinting(opcode,N=100):
    #opcode is a list of different opcodes
    if N>=0:
        CR=opcode[0]
        SR=opcode[1]
        OCSet=set([CR, SR])
        i=2
        while i < N and i< len(opcode):
            if opcode[i] in [CR, SR] and len(OCSet)>=4:
                return False
            OCSet.add(opcode[i])
            i += 1
        return (4 <= len(OCSet)<= 10)