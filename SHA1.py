def left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1(data):
    # Ensure data is in bytes.
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Initial hash values
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Preprocessing: padding the message
    original_byte_len = len(data)
    original_bit_len = original_byte_len * 8

    # Append the bit '1' to the message
    data += b'\x80'

    # Append 0 bits until message length in bits ≡ 448 mod 512
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'

    # Append original length as a 64-bit big-endian integer
    data += original_bit_len.to_bytes(8, byteorder='big')

    # Process the message in successive 512-bit chunks
    for i in range(0, len(data), 64):
        chunk = data[i:i+64]
        # Break chunk into sixteen 32-bit big-endian words w[0..15]
        w = [int.from_bytes(chunk[j*4:j*4+4], byteorder='big') for j in range(16)]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            word = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
            w.append(left_rotate(word, 1))

        # Initialize hash value for this chunk:
        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop:
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:  # 60 <= j <= 79
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to the result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value as a hex string:
    return '{:08x}{:08x}{:08x}{:08x}{:08x}'.format(h0, h1, h2, h3, h4)

