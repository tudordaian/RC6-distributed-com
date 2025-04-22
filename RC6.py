BLOCK_SIZE = 16


class RC6:
    def __init__(self, key: bytes, w=32, r=20):
        """
        key: encryption key
        w: word size in biti
        r: nr de runde
        """
        self.w = w
        self.r = r
        self.b = len(key)
        self.mask = 2 ** w - 1

        self.P = 0xB7E15163
        self.Q = 0x9E3779B9

        self.S = self.key_expansion(key)

    def key_expansion(self, key: bytes) -> list[int]:
        """ Generare round keys din encryption key """
        # Convertire key intr o lista de word uri
        key_words = []
        for i in range(0, len(key), self.w // 8):
            word = 0
            for j in range(min(self.w // 8, len(key) - i)):
                word |= key[i + j] << (j * 8)
            key_words.append(word)

        c = len(key_words) if len(key_words) > 0 else 1
        t = 2 * self.r + 4
        S = [0] * t
        S[0] = self.P
        for i in range(1, t):
            S[i] = (S[i - 1] + self.Q) & self.mask

        # mixare cheie
        A = B = i = j = 0
        v = 3 * max(c, t)
        for s in range(v):
            A = S[i] = self.rotl((S[i] + A + B) & self.mask, 3, self.w)
            B = key_words[j] = self.rotl((key_words[j] + A + B) & self.mask, (A + B) % self.w, self.w)
            i = (i + 1) % t
            j = (j + 1) % c

        return S

    def rotl(self, val, shift, w):
        """ Roteste la stanga val cu shift biti in word size ul w """
        return ((val << shift) | (val >> (w - shift))) & self.mask

    def rotr(self, val, shift, w):
        """ Roteste la dreapta val cu shift biti in word size ul w """
        return ((val >> shift) | (val << (w - shift))) & self.mask

    def pad(self, data: bytes) -> bytes:
        """PKCS padding """
        padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(self, data: bytes) -> bytes:
        padding_length = data[-1]
        if padding_length > BLOCK_SIZE:
            raise ValueError("Invalid padding")
        # verific daca toti bytes de padding au valoarea corecta
        for i in range(1, padding_length + 1):
            if data[-i] != padding_length:
                raise ValueError("Invalid padding")
        return data[:-padding_length]

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """ criptare bloc de 16 bytes """
        if len(plaintext) != BLOCK_SIZE:
            raise ValueError(f"Block must be {BLOCK_SIZE} bytes")

        A = int.from_bytes(plaintext[0:4], byteorder='little')
        B = int.from_bytes(plaintext[4:8], byteorder='little')
        C = int.from_bytes(plaintext[8:12], byteorder='little')
        D = int.from_bytes(plaintext[12:16], byteorder='little')

        B = (B + self.S[0]) & self.mask
        D = (D + self.S[1]) & self.mask
        for i in range(1, self.r + 1):
            t = self.rotl((B * (2 * B + 1)) & self.mask, 5, self.w)
            u = self.rotl((D * (2 * D + 1)) & self.mask, 5, self.w)
            A = self.rotl(A ^ t, u & 0x1F, self.w) + self.S[2 * i]
            C = self.rotl(C ^ u, t & 0x1F, self.w) + self.S[2 * i + 1]
            A &= self.mask
            C &= self.mask

            # Rotire variabile
            A, B, C, D = B, C, D, A

        A = (A + self.S[2 * self.r + 2]) & self.mask
        C = (C + self.S[2 * self.r + 3]) & self.mask

        # Convertire word uri in bytes
        ciphertext = bytearray(16)
        ciphertext[0:4] = A.to_bytes(4, byteorder='little')
        ciphertext[4:8] = B.to_bytes(4, byteorder='little')
        ciphertext[8:12] = C.to_bytes(4, byteorder='little')
        ciphertext[12:16] = D.to_bytes(4, byteorder='little')

        return bytes(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        # adaugare padding la multiplu de 16
        padded_plaintext = self.pad(plaintext)

        # procesare fiecare bloc si combinare a rezultatelor
        result = bytearray()
        for i in range(0, len(padded_plaintext), BLOCK_SIZE):
            block = padded_plaintext[i:i + BLOCK_SIZE]
            encrypted_block = self.encrypt_block(block)
            result.extend(encrypted_block)

        return bytes(result)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """ decriptare bloc de 16 bytes """
        if len(ciphertext) != BLOCK_SIZE:
            raise ValueError(f"Block must be {BLOCK_SIZE} bytes")

        # Convertire ciphertext in 4 words (A, B, C, D)
        A = int.from_bytes(ciphertext[0:4], byteorder='little')
        B = int.from_bytes(ciphertext[4:8], byteorder='little')
        C = int.from_bytes(ciphertext[8:12], byteorder='little')
        D = int.from_bytes(ciphertext[12:16], byteorder='little')

        C = (C - self.S[2 * self.r + 3]) & self.mask
        A = (A - self.S[2 * self.r + 2]) & self.mask

        for i in range(self.r, 0, -1):
            # rotire variabile
            A, B, C, D = D, A, B, C

            u = self.rotl((D * (2 * D + 1)) & self.mask, 5, self.w)
            t = self.rotl((B * (2 * B + 1)) & self.mask, 5, self.w)
            C = self.rotr((C - self.S[2 * i + 1]) & self.mask, t & 0x1F, self.w) ^ u
            A = self.rotr((A - self.S[2 * i]) & self.mask, u & 0x1F, self.w) ^ t

        D = (D - self.S[1]) & self.mask
        B = (B - self.S[0]) & self.mask

        # convertire word uri in bytes
        plaintext = bytearray(16)
        plaintext[0:4] = A.to_bytes(4, byteorder='little')
        plaintext[4:8] = B.to_bytes(4, byteorder='little')
        plaintext[8:12] = C.to_bytes(4, byteorder='little')
        plaintext[12:16] = D.to_bytes(4, byteorder='little')

        return bytes(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError(f"Ciphertext length must be a multiple of {BLOCK_SIZE}")

        # procesare fiecare bloc si combinare a rezultatelor
        result = bytearray()
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            decrypted_block = self.decrypt_block(block)
            result.extend(decrypted_block)

        return self.unpad(result)


key = b"super secret key"
rc6 = RC6(key)


plaintext = b"mesaj lung de lungime foarte mareeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
ciphertext = rc6.encrypt(plaintext)
decrypted = rc6.decrypt(ciphertext).decode('utf-8')

print(decrypted)