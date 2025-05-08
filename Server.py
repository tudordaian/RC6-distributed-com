import base64
import json

import websockets

from RC6 import RC6
from DHKeyExchange import DHKeyExchange


class Server:
    def __init__(self, host='0.0.0.0', port=8765):
        self.host = host
        self.port = port
        self.rc6 = None
        self.dh = DHKeyExchange()
        self.CHUNK_SIZE = 256 * 1024  # 256KB

    async def handle_connection(self, websocket):
        print(f"Client connected from {websocket.remote_address}")

        active_transfer = None

        try:
            _, public_key = self.dh.get_parameters_and_public_key()

            # trimite parametrii DH si cheie publica catre client
            await websocket.send(json.dumps({
                'type': 'dh_init',
                'public_key': base64.b64encode(public_key).decode('utf-8')
            }))

            async for message in websocket:
                data = json.loads(message)

                # key exchange
                if data['type'] == 'dh_response':
                    client_public_key = base64.b64decode(data['public_key'])

                    # generare cheie shared
                    rc6_key = self.dh.generate_shared_key(client_public_key)
                    self.rc6 = RC6(rc6_key)
                    print("Key exchange completed")

                # handler mesaje
                elif data['type'] == 'message' and self.rc6:
                    encrypted_data = base64.b64decode(data['data'])
                    decrypted_data = self.rc6.decrypt(encrypted_data)
                    print(f"Received message: {decrypted_data.decode('utf-8')}")


                # initiere transfer fisier
                elif data['type'] == 'file_start' and self.rc6:
                    if active_transfer is not None:
                        print("Another transfer is in progress")
                        continue

                    filename = data['filename']
                    encrypted_filename = f"{filename}(encrypted)"
                    active_transfer = {
                        'filename': filename,
                        'encrypted_filename': encrypted_filename,
                        'size': data['size'],
                        'total_chunks': data['total_chunks'],
                        'received_chunks': 0,
                        'file_handle': open(filename, 'wb'),
                        'encrypted_file_handle': open(encrypted_filename, 'wb')
                    }
                    print(f"Starting file transfer: {filename} ({data['size']} bytes, {data['total_chunks']} chunks)")

                elif data['type'] == 'file_chunk' and self.rc6 and active_transfer:
                    encrypted_chunk = base64.b64decode(data['data'])

                    # salvare chunk criptat
                    active_transfer['encrypted_file_handle'].write(encrypted_chunk)

                    # decriptare si salvare chunk
                    decrypted_chunk = self.rc6.decrypt(encrypted_chunk)
                    chunk_id = data['chunk_id']
                    file_position = chunk_id * self.CHUNK_SIZE
                    active_transfer['file_handle'].seek(file_position)
                    active_transfer['file_handle'].write(decrypted_chunk)
                    active_transfer['received_chunks'] += 1

                    # progress bar
                    progress = (active_transfer['received_chunks'] / active_transfer['total_chunks']) * 100
                    print(
                        f"\rReceiving {active_transfer['filename']}: {progress:.1f}% ({active_transfer['received_chunks']}/{active_transfer['total_chunks']} chunks)",
                        end="")

                # completare transfer fisier
                elif data['type'] == 'file_end' and self.rc6 and active_transfer:
                    filename = active_transfer['filename']
                    encrypted_filename = active_transfer['encrypted_filename']
                    active_transfer['file_handle'].close()
                    active_transfer['encrypted_file_handle'].close()
                    print(f"\nFile {filename} received successfully")

                    active_transfer = None

        except Exception as e:
            print(f"Error: {e}")
        finally:
            # cleanup pt file transfer
            if active_transfer:
                if 'file_handle' in active_transfer:
                    active_transfer['file_handle'].close()
                if 'encrypted_file_handle' in active_transfer:
                    active_transfer['encrypted_file_handle'].close()

            print(f"Client disconnected")

    async def start_server(self):
        server = await websockets.serve(self.handle_connection, self.host, self.port)
        print(f"Server started on {self.host}:{self.port}")
        await server.wait_closed()