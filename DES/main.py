import utils


def permutation(x, inverse=False):
    x = x[2:]
    x_permutated = "0b"
    for i in range(64):
        if not inverse:
            x_permutated += x[utils.IP[i] - 1]
        else:
            x_permutated += x[utils.INVERSE_IP[i] - 1]
    return x_permutated


def get_round_keys(key):
    if len(key[2:]) < 64 and key[:2] == "0b":
        key = "0" * (64 - len(key[2:])) + key[2:]

    PC1_key = ""
    for i in range(56):
        PC1_key += key[utils.PC1[i] - 1]

    c0 = PC1_key[:28]
    d0 = PC1_key[28:]

    round_keys = []
    for i in range(16):
        if i in [0, 1, 8, 15]:
            c = c0[1:] + c0[:1]
            d = d0[1:] + d0[:1]
        else:
            c = c0[2:] + c0[:2]
            d = d0[2:] + d0[:2]
        ci_di = c + d
        c0 = c
        d0 = d

        round_key = "0b"
        for j in range(48):
            round_key += ci_di[utils.PC2[j] - 1]
        round_keys.append(round_key)
    return round_keys


def E(A):
    A = A[2:]
    A_expanded = "0b"

    for i in range(48):
        A_expanded += A[utils.EXP[i] - 1]
    return A_expanded


def f(A, J):
    B = bin(int(E(A), 2) ^ int(J, 2))
    if len(B[2:]) < 48 and B[:2] == "0b":
        B = "0" * (48 - len(B[2:])) + B[2:]
    else:
        if len(B[2:]) == 48 and B[:2] == "0b":
            B = B[2:]

    divided_B = []
    for i in range(8):
        divided_B.append(B[(i * 6):((i + 1) * 6)])
    C = ""
    for i in range(8):
        row = int("0b" + divided_B[i][0] + divided_B[i][5], 2)
        col = int("0b" + divided_B[i][1:5], 2)
        C_i = bin(utils.S_BOXES[i][row][col])[2:]
        if len(C_i) < 4:
            C_i = "0" * (4 - len(C_i)) + C_i
        C += C_i

    P_C = "0b"
    for i in range(len(C)):
        P_C += C[utils.P[i] - 1]
    return P_C


def DES(x, key, encrypt=True):
    if len(x[2:]) < 64 and x[:2] == "0b":
        x = "0b" + "0" * (64 - len(x[2:])) + x[2:]

    x_permutated = permutation(x)

    l0 = x_permutated[:34]
    r0 = "0b" + x_permutated[34:]

    round_keys = get_round_keys(key)

    if not encrypt:
        round_keys.reverse()

    r = ""
    l = ""
    for i in range(16):
        l = r0
        r = bin(int(l0, 2) ^ int(f(r0, round_keys[i]), 2))
        if len(r[2:]) < 32 and r[:2] == "0b":
            r = "0b" + "0" * (32 - len(r[2:])) + r[2:]
        l0 = l
        r0 = r

    return int(permutation(r + l[2:], inverse=True), 2)


def main():
    plaintext = "0x0123456789ABCDEF"
    print("Plaintext: " + plaintext)
    plaintext = bin(int(plaintext, 16))

    key = "0x133457799BBCDFF1"
    key = bin(int(key, 16))

    encrypted_text = DES(plaintext, key)
    print("Encrypted Text using DES: " + hex(encrypted_text))

    decrypted_text = DES(bin(encrypted_text), key, encrypt=False)
    print("Decrypted Text: " + hex(decrypted_text))









    print("============================================")
    k1 = bin(int(hex(200 ** 8), 16))
    k2 = bin(int(hex(231 ** 8), 16))
    print("K1 is: " + k1)
    print("K2 is: " + k2)

    encrypted_text = DES(plaintext, k1)
    print("Encrypted: " + hex(encrypted_text))
    if len(hex(encrypted_text)[2:]) < 16:
        encrypted_text = "0x" + "0" * (16 - len(hex(encrypted_text)[2:])) + hex(encrypted_text)[2:]
    encrypted_text = bin(int(hex(encrypted_text), 16))
    double_encrypted_text = hex(DES(encrypted_text, k2))
    print("Double Encrypted: " + double_encrypted_text)

    first_key_encrypted_text = {}
    # 2 ** 8 => invalid literal for int() with base 2:
    # '0b1001101--0b010100010000000010010000111100001110000'
    for i in range(235):
        first_key = bin(int(hex(i ** 8), 16))
        first_key_encrypted_text[hex(DES(plaintext, first_key))] = first_key

    for i in range(235):
        second_key = bin(int(hex(i ** 8), 16))
        curr_decrypt = DES(bin(int(double_encrypted_text, 16)), second_key, encrypt=False)

        if hex(curr_decrypt) in first_key_encrypted_text:
            print("K1: " + first_key_encrypted_text[hex(curr_decrypt)])
            print("K2: " + second_key)


if __name__ == '__main__':
    main()

