def opcode_fingerprinting(opcodes):
    # opcodes is a list of different opcodes
    CR=opcodes[0]
    SR=opcodes[1]
    OCSet=set([CR, SR])
    for opcode in opcodes:
        if opcode in [CR, SR] and len(OCSet)>=4:
            return False
        OCSet.add(opcode)
    return 4 <= len(OCSet) <= 10
