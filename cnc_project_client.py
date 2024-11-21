from enum import Enum
import os
import socket
import rsa

IP = "10.180.81.31"
PORT = int(input("Enter port number: "))
ADDR = (IP,PORT)
SIZE = 1024 ## byte .. buffer size
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

def main():
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect(ADDR)
    print(client.recv(SIZE).decode(FORMAT))
    KEY = client.recv(SIZE)
    SID = client.recv(SIZE)
    while True:  ### multiple communications
        data = input("> ")
        data = data.split(" ")
        # data = data[1]
        cmd = data[0]
        cmd = cmd.upper()
        client.send(cmd.encode(FORMAT))
        print(client.recv(SIZE).decode(FORMAT))
'''
        match cmd:
          case "LOGIN":
            client.send(cmd.encode(FORMAT))
            password = input("> ")
            client.send(rsa.encrypt(password.encode(FORMAT), KEY))
          case "OK":
            print(f"{msg}")
          case "DISCONNECT":
            print("Disconnected from the server.")
            client.close() ## close the connection
          case "TASK":
            client.send(cmd.encode(FORMAT))
          case "LOGOUT":
            client.send(cmd.encode(FORMAT))
'''

if __name__ == "__main__":
    main()
