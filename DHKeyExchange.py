from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class DHKeyExchange:
    def __init__(self):
        p = int(
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
            '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
            '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
            '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
            '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
            '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33'
            'A85521ABDF1CBA64ECFB850AE343D2C6B2A47', 16
        )
        g = 2
        parameters_numbers = dh.DHParameterNumbers(p=p, g=g, q=None)
        self.parameters = parameters_numbers.parameters(default_backend())

        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_parameters_and_public_key(self):
        # serializeaza cheia publica pt transmisie
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_bytes

    def generate_shared_key(self, peer_public_key_bytes, key_size=16):
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
            backend=default_backend()
        )

        shared_key = self.private_key.exchange(peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        return derived_key