# CIIC 5018-050 - Cryptography and Network Security
# Project - Hybrid Cryptosystem using Rotor Machine and DES Encryption
# Task 2: DES Implementation
# On messages used in Task 1: "HELLO", "HOPE", "NEW YEAR"
# Authors: Edjoel Colon Nogueras & Christian Medina Diaz

# DES tables (standard)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

S_BOX = [
    # S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
    ],
    # S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
    ],
    # S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
    ],
    # S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
    ],
    # S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
    ],
    # S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
    ],
    # S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
    ],
    # S8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ]
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2,
           1, 2, 2, 2, 2, 2, 2, 1]

# Helper funcs
def permute(block, table):
    return [block[i-1] for i in table]

def rotate_left(block, n):
    return block[n:] + block[:n]

def xor_bits(a, b):
    return [x ^ y for x, y in zip(a, b)]

def bytes_to_bits(data: bytes):
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i+j]
        out.append(byte)
    return bytes(out)

def generate_subkeys(key_64: bytes):
    key_bits = bytes_to_bits(key_64)
    key_56 = permute(key_bits, PC1)
    C = key_56[:28]
    D = key_56[28:]
    subkeys = []
    for s in SHIFTS:
        C = rotate_left(C, s)
        D = rotate_left(D, s)
        CD = C + D
        K = permute(CD, PC2)
        subkeys.append(K)
    return subkeys

def sbox_substitution(bits48):
    out = []
    for i in range(8):
        b = bits48[i*6:(i+1)*6]
        row = (b[0] << 1) | b[5]
        col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4]
        val = S_BOX[i][row][col]
        for j in range(3, -1, -1):
            out.append((val >> j) & 1)
    return out

def feistel(R, subkey):
    R_exp = permute(R, E_TABLE)
    x = xor_bits(R_exp, subkey)
    s = sbox_substitution(x)
    return permute(s, P)

def des_block_encrypt(block8: bytes, subkeys):
    bits = bytes_to_bits(block8)
    perm = permute(bits, IP)
    L, R = perm[:32], perm[32:]
    for i in range(16):
        f = feistel(R, subkeys[i])
        L, R = R, xor_bits(L, f)
    preoutput = R + L
    final_bits = permute(preoutput, FP)
    return bits_to_bytes(final_bits)

def des_block_decrypt(block8: bytes, subkeys):
    bits = bytes_to_bits(block8)
    perm = permute(bits, IP)
    L, R = perm[:32], perm[32:]
    for i in range(15, -1, -1):
        f = feistel(R, subkeys[i])
        L, R = R, xor_bits(L, f)
    preoutput = R + L
    final_bits = permute(preoutput, FP)
    return bits_to_bytes(final_bits)

def pad_pkcs5(data: bytes):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len]) * pad_len

def unpad_pkcs5(data: bytes):
    pad_len = data[-1]
    return data[:-pad_len]

# Test for Task 2
if __name__ == "__main__":
    key = bytes.fromhex("133457799BBCDFF1")
    subkeys = generate_subkeys(key)

    messages = ["HOPE", "HELLO", "NEW YEAR"]

    for m in messages:
        # Encrypt
        pt_bytes = m.encode("ascii")
        pt_padded = pad_pkcs5(pt_bytes)
        ct = b""
        for i in range(0, len(pt_padded), 8):
            ct += des_block_encrypt(pt_padded[i:i+8], subkeys)

        # Decrypt
        recovered = b""
        for i in range(0, len(ct), 8):
            recovered += des_block_decrypt(ct[i:i+8], subkeys)
        recovered = unpad_pkcs5(recovered)

        print("Plaintext :", m)
        print("Ciphertext:", ct.hex().upper())
        print("Decrypted :", recovered.decode("ascii"))
        print("-" * 40)
