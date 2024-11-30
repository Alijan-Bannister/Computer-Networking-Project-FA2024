from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from tkinter import filedialog as fd
import base64
import os
import rsa
import time


IP = "10.180.80.67"
PORT = int(input("Enter port number: "))
ADDR = (IP,PORT)
SIZE = 1024 ## byte .. buffer size
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

length_received: float = 0


def receive_status_msgs(client: socket, length_to_send: int):
  print("receiving msgs")
  global length_received

  while length_received < length_to_send:
    length_received = int(client.recv(SIZE).decode(FORMAT).split('@')[1])
    print(f'Upload Status: {length_received} / {length_to_send}: {length_received / length_to_send * 100:.2f}% Complete...')

  client.send("ACK@".encode(FORMAT))


def main():
  client = socket(AF_INET, SOCK_STREAM)
  client.connect(ADDR)
  print(client.recv(SIZE).decode(FORMAT))

  KEY = rsa.PublicKey.load_pkcs1(client.recv(SIZE))
  ack = "ACK@"
  client.send(ack.encode(FORMAT))

  SID = client.recv(SIZE)
  client.send(ack.encode(FORMAT))

  while True:  ### multiple communications
    cmd = input("> ").upper()

    match cmd:
      case "UPLOAD":
        try:
          file_path: str = fd.askopenfilename(title="Select a file")
        except FileNotFoundError:
          print("Upload canceled")
          continue

        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        desired_directory = input("Enter directory to upload to: ")
        client.send((cmd + "@" + desired_directory + " | " + file_name + " | " + str(file_size)).encode(FORMAT))

        response = client.recv(SIZE).decode(FORMAT)
        if not response.startswith("OK@"):
          continue

        client.send(ack.encode(FORMAT))
        
        print(f"Sending {file_path}...")

        global upload_status
        upload_status = 0

        status_thread: Thread = Thread(target=receive_status_msgs, args=(client, file_size))
        status_thread.start()
        time.sleep(0.5)

        with open(file_path, 'rb') as file:
          client.sendfile(file)

        status_thread.join()

        response = client.recv(SIZE).decode(FORMAT)
        print(response)

        if response.startswith("OVERWRITE@"):
          overwrite = input("A file with the same name exists at that location, would you like to overwrite the file? (Y/N): ")
          if overwrite != 'Y' and overwrite != 'N':
            print("Response not recognized")
            continue

          client.send(f"OVERWRITE@{int(overwrite == 'Y')}".encode(FORMAT))
         # response = client.recv(SIZE).decode(FORMAT)
      case "LOGIN":
        username = input("Username: ")
        password = input("Password: ")
        password = password.encode(FORMAT) + SID
        password = rsa.encrypt(password, KEY)
        password = base64.b64encode(password).decode(FORMAT)
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
      case "DOWNLOAD":
        file_data: bytes = b""
        path = input("Specify the path of the file you want to download: ")
        local_path = input("Where fo you want to put the file: ")
        if os.path.exists(local_path):
          cmd = f"DOWNLOAD@{path}"
          client.sendall(cmd.encode(FORMAT))
          if client.recv(SIZE).decode(FORMAT) == "OK":
            file_length: int = int(client.recv(SIZE))
            while True:
              file_data += client.recv(file_length - len(file_data))
              if len(file_data) >= file_length:
                break
            with open(local_path, "wb") as file:
              file.write(file_data)
          else:
            print("error occured on server end")
        else:
          print(f"{local_path} doesn't exist")



    print(client.recv(SIZE).decode(FORMAT))


if __name__ == "__main__":
  main()


if __name__ == "__main__":
  main()
