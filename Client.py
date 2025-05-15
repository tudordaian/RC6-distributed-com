import base64
import json
import os

import websockets

from DHKeyExchange import DHKeyExchange
from RC6 import RC6


class Client:
    def __init__(self, uri='ws://localhost:8765'):
        self.uri = uri
        self.rc6 = None
        self.dh = DHKeyExchange()
        self.websocket = None

    async def connect(self):
        self.websocket = await websockets.connect(self.uri)
        print(f"Connected to {self.uri}")

        await self.key_exchange()

        return self.websocket

    async def key_exchange(self):
        # primeste parametrii serverului si public key
        message = await self.websocket.recv()
        data = json.loads(message)

        if data['type'] == 'dh_init':
            # decodeaza cheia publica a serverului
            server_public_key = base64.b64decode(data['public_key'])

            # primeste cheia publica a clientului
            client_public_key = self.dh.get_parameters_and_public_key()

            # trimite cheia publica a clientului catre server
            await self.websocket.send(json.dumps({
                'type': 'dh_response',
                'public_key': base64.b64encode(client_public_key).decode('utf-8')
            }))

            # genereaza shared key din cheia publica a serverului
            rc6_key = self.dh.generate_shared_key(server_public_key)
            self.rc6 = RC6(rc6_key)
            print("Key exchange completed")

    async def send_message(self, message):
        if not self.rc6:
            print("Cannot send: Key exchange not complete")
            return

        encrypted_message = self.rc6.encrypt(message.encode('utf-8'))
        await self.websocket.send(json.dumps({
            'type': 'message',
            'data': base64.b64encode(encrypted_message).decode('utf-8')
        }))

    async def send_file(self, filepath):
        if not self.rc6:
            print("Cannot send file: Key exchange not complete")
            return

        try:
            # get marimea fisierului si numele
            file_size = os.path.getsize(filepath)
            filename = os.path.basename(filepath)


            CHUNK_SIZE = 256 * 1024 # 256 kb
            total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

            # send metadatele fisierului
            await self.websocket.send(json.dumps({
                'type': 'file_start',
                'filename': filename,
                'size': file_size,
                'total_chunks': total_chunks
            }))

            # trimit fisieru in chunkuri
            with open(filepath, 'rb') as f:
                sent_chunks = 0

                for chunk_id in range(total_chunks):
                    # citire si criptare chunk
                    chunk_data = f.read(CHUNK_SIZE)
                    encrypted_chunk = self.rc6.encrypt(chunk_data)

                    # send chunk
                    await self.websocket.send(json.dumps({
                        'type': 'file_chunk',
                        'chunk_id': chunk_id,
                        'data': base64.b64encode(encrypted_chunk).decode('utf-8')
                    }))

                    # progress bar
                    sent_chunks += 1
                    progress = (sent_chunks / total_chunks) * 100
                    print(f"\rSending {filename}: {progress:.1f}% ({sent_chunks}/{total_chunks} chunks)", end="")

                # trimite markerul file_end
                await self.websocket.send(json.dumps({
                    'type': 'file_end',
                    'filename': filename
                }))

                print(f"\nFile {filename} sent successfully")

        except Exception as e:
            print(f"\nError sending file: {e}")

    async def close(self):
        if self.websocket:
            await self.websocket.close()
            print("Connection closed")