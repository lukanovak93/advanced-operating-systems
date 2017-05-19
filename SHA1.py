import sys

class SHA_1:
    def __init__(self):
        self.__H = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
            ]

    def to_string(self):
        return ''.join((hex(i)[2:]).rjust(8, '0') for i in self.__H)


    @staticmethod
    def left_rotate(n, x, w=32):
        """Left rotate a 32-bit integer n by b bits."""
        return ((x << n) | (x >> w - n))


    @staticmethod
    def pad(stream):
        # in bytes
        length = len(stream)
        h_length = [int((hex(length*8)[2:]).rjust(16, '0')[i:i+2], 16)
              for i in range(0, 16, 2)]

        l0 = (56 - length) % 64
        if not l0:
            l0 = 64

        if isinstance(stream, str):
            stream += chr(0b10000000)
            stream += chr(0)*(l0-1)
            for a in h_length:
                stream += chr(a)
        elif isinstance(stream, bytes):
            stream += bytes([0b10000000])
            stream += bytes(l0-1)
            stream += bytes(h_length)

        return stream

    @staticmethod
    def prep(stream):
        M = []
        n = len(stream) // 64

        stream = bytearray(stream)

        for i in range(n):  # 64 Bytes per Block
            m = []

            for j in range(16):  # 16 Words per Block
                p = 0
                for k in range(4):  # 4 Bytes per Word
                    p <<= 8
                    p += stream[i*64 + j*4 + k]

                m.append(n)

            M.append(m[:])

        return M

    def block_proc(self, block):
        VAL = 2**32-1

        W = block[:]
        for t in range(16, 80):
            W.append(SHA_1.left_rotate(1, (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]))
                     & VAL)

        a, b, c, d, e = self.__H[:]

        for t in range(80):
            if t <= 19:
                K = 0x5a827999
                # function = (B AND C) OR ((NOT B) AND D)
                f = (b & c) | (~b & d)
            elif (t >= 20 and t <= 39):
                K = 0x6ed9eba1
                #function = B XOR C XOR D
                f = b ^ c ^ d
            elif (t >= 40 and t <= 59):
                K = 0x8f1bbcdc
                # tunction = (B AND C) OR (B AND D) OR (C AND D)
                f = (b & c) | (b & d) | (c & d)
            else:
                K = 0xca62c1d6
                # function = B XOR C XOR D
                f = b ^ c ^ d

            T = ((SHA_1.left_rotate(5, a) + f + e + K + W[t]) & VAL)
            e = d
            d = c
            c = SHA_1.left_rotate(30, b) & VAL
            b = a
            a = T

            #SHA_1.debug_print(t, a,b,c,d,e)

        self.__H[0] = (a + self.__H[0]) & VAL
        self.__H[1] = (b + self.__H[1]) & VAL
        self.__H[2] = (c + self.__H[2]) & VAL
        self.__H[3] = (d + self.__H[3]) & VAL
        self.__H[4] = (e + self.__H[4]) & VAL


    def update(self, stream):
        stream = SHA_1.pad(stream)
        stream = SHA_1.prep(stream)

        for block in stream:
            self.block_proc(block)

    def hex_result(self):
        s = ''
        for h in self.__H:
            s += (hex(h)[2:]).rjust(8, '0')
        return s


def main():

    if len(sys.argv) < 2:
        print('Usage: python SHA_1.py <file> [<file> ...]')
        sys.exit()

    for filename in sys.argv[1:]:
        try:
            with open(filename, 'rb') as f:
                content = f.read()

        except:
            print ('ERROR: Input file "{0}" cannot be read.'.format(filename))

        else:
            hex = SHA_1()
            hex.update(content)
            hex_SHA_1 = hex.hex_result()
            print("{0}  {1}".format(hex_SHA_1, filename))


if __name__ == '__main__':
    main()
