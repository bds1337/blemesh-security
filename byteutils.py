
def bxor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def bor(ba1, ba2):
    return bytes([_a | _b for _a, _b in zip(ba1, ba2)])