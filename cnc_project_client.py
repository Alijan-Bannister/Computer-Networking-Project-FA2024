import os
import socket
from tkinter import filedialog as fd
from cryptography.fernet import Fernet


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
    publickey = Fernet(KEY)
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

                file_size = os.path.getsize(file_path)
                directorypath,filename = os.path.split(file_path)

                desiredDirectory = input("Enter directory to upload to: ")
                client.send((cmd + "@" + desiredDirectory + " | " + filename + " | " + str(file_size)).encode(FORMAT))

                ack = client.recv(SIZE).decode(FORMAT)
                if not ack.startswith("OK@"):
                    continue

                with open(file_path, 'rb') as file:
                    print(f"Sending {file_path}...")
                    client.sendfile(file)

            case "LOGIN":
                username = input("Username: ")
                password = input("password: ")
                password = password.encode(FORMAT) + SID
                print(password)
                password = publickey.encrypt(password)
                password = password.decode(FORMAT)
                cmd = f"LOGIN@{username} | {password}"
                client.sendall(cmd.encode(FORMAT))
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
                else:
                    print("Invalid Input")
        print(client.recv(SIZE).decode(FORMAT))


if __name__ == "__main__":
    main()
