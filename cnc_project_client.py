from tkinter import filedialog as fd
import base64
import os
import rsa
import socket


IP = "10.0.0.209"
PORT = int(input("Enter port number: "))
ADDR = (IP,PORT)
SIZE = 1024 ## byte .. buffer size
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"


def main():
  client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  client.connect(ADDR)
  print(client.recv(SIZE).decode(FORMAT))

  KEY = rsa.PublicKey.load_pkcs1(client.recv(SIZE))
  ack = "ACK@"
  client.send(ack.encode(FORMAT))

  SID = client.recv(SIZE)
  client.send(ack.encode(FORMAT))

  while True:  ### multiple communications
    data = input("> ")
    cmd = data.upper()
    # data = data[1])

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

        with open(file_path, 'rb') as file:
          print(f"Sending {file_path}...")
          client.sendfile(file)

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
    print(client.recv(SIZE).decode(FORMAT))


if __name__ == "__main__":
  main()
