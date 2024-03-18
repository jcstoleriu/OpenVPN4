def opcode_fingerprinting(opcodes):
    # opcodes is a list of different opcodes
    if len(opcodes) < 2:
        return False
    CR=opcodes[0]
    SR=opcodes[1]
    OCSet=set()
    for opcode in opcodes:
        if opcode in [CR, SR] and len(OCSet)>=4:
            return False
        OCSet.add(opcode)
    return 4 <= len(OCSet) <= 10
