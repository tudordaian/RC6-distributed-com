import asyncio
import sys

from Client import Client
from Server import Server

# ruleaza ifconfig
# server_ip = '192.168.1.135' # wifi acasa
# SERVER_IP = '172.20.10.3' # hotspot
SERVER_IP = '0.0.0.0'

async def run_server():
    server = Server()
    await server.start_server()



async def run_client(server_ip='localhost'):
    client = Client(uri=f'ws://{server_ip}:8765')
    await client.connect()

    try:
        while True:
            command = input("Enter command (message/file/quit): ").strip()

            if command.lower() == 'quit':
                break
            elif command.lower() == 'message':
                message = input("Enter message: ")
                await client.send_message(message)
            elif command.lower() == 'file':
                filepath = input("Enter file path: ")
                await client.send_file(filepath)
            else:
                print('Unknown command')
    finally:
        await client.close()


if __name__ == "__main__":
    mode = sys.argv[1].lower()

    if mode == 'server':
        asyncio.run(run_server())
    elif mode == 'client':
        asyncio.run(run_client(SERVER_IP))
    else:
        print("Invalid mode. Use 'server' or 'client'")
