from enum import Enum
import os
import socket
import rsa
import pathlib
import tkinter
from tkinter import filedialog as fd


IP = "10.180.82.224"
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
    ok = "ACK@"
    client.send(ok.encode(FORMAT))

    SID = client.recv(SIZE)
    client.send(ok.encode(FORMAT))

    while True:  ### multiple communications
        data = input("> ")
        cmd = data.upper()
        # data = data[1])

        match cmd:

            case "UPLOAD":

                file_path: str = fd.askopenfilename(title="Select a file")
                print(file_path)
                with open(file_path, 'rb') as file:
                    print(f"Sending {file_path}...")
                file_size = os.path.getsize(file_path)
                directorypath,filename = os.path.split(file_path)

                client.send((cmd + "@" + directorypath + " | " + filename + str(file_size)).encode(FORMAT))

            case "DIR":
                client.send((cmd + '@').encode(FORMAT))

            case "DELETE":
                filepath = input("File path: ")
                client.send((cmd + "@" + filepath).encode(FORMAT))

            case "SUBFOLDER":
                folderOption = input("create/delete?: ")
                if folderOption.upper() == "CREATE":
                    filePath = input("Parent path: ")
                    dirName = input("New Directory Name: ")
                    client.send((cmd + "@" + folderOption.upper() + " | " + filePath + " | " + dirName).encode(FORMAT))
                if folderOption.upper() == "DELETE":
                    filePath = input("Path to Delete: ")
                    client.send((cmd + "@" + folderOption.upper() + " | " + filePath).encode(FORMAT))
            case _:
                client.send(cmd.encode(FORMAT))

        print(client.recv(SIZE).decode(FORMAT))
if __name__ == "__main__":
    main()
    