import struct

def sha256_new(message):
    # вводимо геш значення
    h0 = 0x0a09e667
    h1 = 0xbb67ae85
    h2 = 0x1c6ef372
    h3 = 0xa57ff53a
    h4 = 0x511e527f
    h5 = 0x9b05608c
    h6 = 0x1f83d9ab
    h7 = 0x8be0cd19

    # вводимо константи
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # функція гешування
    message = bytearray(message, 'utf-8')
    ml = len(message) * 8
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += struct.pack('>Q', ml)

    for i in range(0, len(message), 64):
        # Break chunk into sixteen 32-bit big-endian words w[i]
        w = list(struct.unpack('>16L', message[i:i+64]))

        # вводимо змінні для дошифрування
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        # основна функція
        for j in range(64):
            if j < 16:
                s0 = (w[j] >> 2) | (w[j] << 30)
                s1 = (w[j] >> 13) | (w[j] << 19)
                s2 = (w[j] >> 22) | (w[j] << 10)
                s = s0 ^ s1 ^ s2
            else:
                s0 = (w[(j-15) & 0x0f] >> 7) | (w[(j-15) &0x0f] << 25)
                s1 = (w[(j-15) & 0x0f] >> 18) | (w[(j-15) & 0x0f] << 14)
                s2 = w[(j-15) & 0x0f] >> 3
                s3 = (w[(j-15) & 0x0f] << 29) | (w[(j-14) & 0x0f] >> 3)
                s4 = (w[(j-14) & 0x0f] >> 10) | (w[(j-14) & 0x0f] << 22)
                s = (s0 ^ s1 ^ s2 ^ s3 ^ s4)

            s0 = (a >> 2) | (a << 30)
            s1 = (a >> 13) | (a << 19)
            s2 = (a >> 22) | (a << 10)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 ^ s1 ^ s2 + maj
            s0 = (e >> 6) | (e << 26)
            s1 = (e >> 11) | (e << 21)
            s2 = (e >> 25) | (e << 7)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s0 + ch + k[j] + w[j]
            h, g, f, e, d, c, b, a = g, f, e, (d + t1), c, b, a, (t1 + t2)

        # отримуємо результати
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff

    return '{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}'.format(h0, h1, h2, h3, h4, h5, h6, h7)
