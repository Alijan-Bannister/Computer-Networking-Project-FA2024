from enum import Enum
from socket import socket as Socket
from threading import Thread
from tkinter import filedialog as fd
import base64
import os
import rsa
import socket
import time


# response codes
class Response(Enum):
  OK = "OK" # request successful
  ACK = "ACK" # acknowledge
  INFO = "INFO" # unsolicited information
  OVERWRITE = "OVERWRITE" # whether the user wants to overwrite the file
  KEY = "KEY" # contains a public key/session ID
  BAD = "BAD_REQUEST" # bad syntax
  UNAUTH = "UNAUTHORIZED" # not logged in
  FORBID = "FORBIDDEN" # not allowed (after log in)
  NOT_FOUND = "NOT_FOUND" # file or directory not found
  REJECT = "REJECTED" # the request is recognized and properly formatted but was rejected


# command codes
class Command(Enum):
  LOGIN = 'LOGIN'
  LOGOUT = 'LOGOUT'
  UPLOAD = 'UPLOAD'
  DOWNLOAD = 'DOWNLOAD'
  DIR = 'DIR'
  SUBFOLDER = 'SUBFOLDER'
  DELETE = 'DELETE'
  DISCONNECT = 'DISCONNECT'


IP = input('Enter the server IP address: ')
PORT = int(input('Enter server port number: '))
ADDR = (IP, PORT)
SIZE = 1024  # bytes
FORMAT = "utf-8"


# recieve upload status messages from the server
def receive_status_msgs(conn: Socket, length_to_send: int):
  length_received: int = 0

  # receive updates while the server still hasn't received all the data
  while length_received < length_to_send:
    # receive a status update on the upload from the server
    length_received = int(get_msg(recv_msg(conn)))

    # display the upload status
    print(f'Upload Status: {length_received} / {length_to_send}: {length_received / length_to_send * 100:.2f}% Complete...', end='\r')

  # upload complete
  print(f'{'File sent':100}')
  send_message(conn, Response.ACK)


# send a message with the given response or command code and additional information to the server
def send_message(conn: Socket, code: Response | Command, *msg: str):
  conn.sendall(f'{code.value}@{' | '.join(msg)}'.encode(FORMAT))


# check if the given message starts with the given response code
def check_response_code(msg: str, code: Response) -> bool:
  return msg.startswith(code.value + '@')


# return the code and actual message extracted from the message
def get_code_and_msg(msg: str) -> tuple[Response, str]:
  parts: list[str] = msg.split('@')
  return (Response(parts[0]), parts[1] if len(parts) == 2 else '')


# return the actual message in the message (without the response code)
def get_msg(msg: str) -> str:
  return msg.split('@')[1]


# receive a string message from the server
def recv_msg(conn: Socket, size: int=SIZE) -> str:
  return conn.recv(size).decode(FORMAT)


def main() -> None:
  # connect to the server
  conn: Socket = Socket(socket.AF_INET, socket.SOCK_STREAM)
  conn.connect(ADDR)

  # receive the welcome message
  msg: str = recv_msg(conn)

  # if the message received wasn't the welcome message, display an error message
  if not check_response_code(msg, Response.OK) and get_msg(msg).upper().startswith('WELCOME'):
    print('Something went wrong, unable to connect to the server')
    return

  print('Connected to the server')

  # get the public key from the server
  key: rsa.PublicKey = rsa.PublicKey.load_pkcs1(conn.recv(SIZE))
  send_message(conn, Response.ACK)

  # get the session ID from the server
  session_id: bytes = conn.recv(SIZE)
  send_message(conn, Response.ACK)

  # accept user commands
  while True:
    # get the command the user wants to enter
    entered_cmd: str = input("Enter a command: ").upper()

    # check if the command the user entered is valid
    try:
      cmd: Command = Command(entered_cmd)
    except ValueError:
      print('Command not recognized')
      continue

    # execute the functionality for the command the user entered
    match cmd:
      case Command.UPLOAD:
        # ask the user to select a file to upload to the server
        try:
          file_path: str = fd.askopenfilename(title="Select a file to upload")
        except FileNotFoundError:
          print("Upload canceled")
          continue

        # get the name and file size of the file the user selected
        file_name: str = os.path.basename(file_path)
        file_size: int = os.path.getsize(file_path)

        # ask the user to enter a directory in the server to upload the file to
        desired_directory: str = input("Enter server directory to upload to: ")

        # send the upload request to the server
        send_message(conn, Command.UPLOAD, desired_directory, file_name, str(file_size))

        # get the server's response to the request
        response: str = recv_msg(conn)

        # if the server did not say to proceed with the upload, don't
        if not check_response_code(response, Response.OK):
          continue

        send_message(conn, Response.ACK)

        print(f"Sending {file_path}...")

        # start a thread which will receive and print out status messages from the server regarding the file upload
        status_thread: Thread = Thread(target=receive_status_msgs, args=(conn, file_size))
        status_thread.start()
        time.sleep(0.5)

        # send the file
        with open(file_path, 'rb') as file:
          conn.sendfile(file)

        # wait for the status messages to finish printing
        status_thread.join()

        # receive the server's response to the upload
        response = conn.recv(SIZE).decode(FORMAT)
        print(response)

        # if the file would be overwritten if uploaded to the server
        if check_response_code(response, Response.OVERWRITE):
          # ask the user to confirm whether they want to overwrite the file
          overwrite: str = input("The uploaded file already exists, would you like to overwrite the file? (Y/N): ").upper()

          # if the user did not enter yes or no, the response isn't recognized
          if overwrite != 'Y' and overwrite != 'N':
            print("Response not recognized")
            continue

          # send whether the user wants to overwrite the message to the server
          send_message(conn, Response.OVERWRITE, str(int(overwrite == 'Y')))

          print(recv_msg(conn))
          print(recv_msg(conn))
      case Command.LOGIN:
        # get the username and password from the user
        user: str = input("Username: ")
        pwd: str = input("Password: ")

        # combine the password and session ID, encrypt the data, and base64 encode the data
        pwd_sid: bytes = pwd.encode(FORMAT) + session_id
        enc_data: bytes = rsa.encrypt(pwd_sid, key)
        encoded_data: str = base64.b64encode(enc_data).decode(FORMAT)

        # send the user's credentials to the server
        send_message(conn, Command.LOGIN, user, encoded_data)

        print(recv_msg(conn))
      case Command.LOGOUT:
        # request the server to logout the user
        send_message(conn, Command.LOGOUT)

        # get the server's response
        response = recv_msg(conn)

        # if the sever did not say the logout was successful, something went wrong
        if not check_response_code(response, Response.OK):
          print('Logout Failed')
          continue

        # the user has been logged out successfully
        print('You have been logged out successfully')
        break
      case Command.DISCONNECT:
        # send the disconnect request to the server
        send_message(conn, Command.DISCONNECT)

        # disconnect
        break
      case Command.DIR:
        # ask the server for the file storage directory structure
        send_message(conn, Command.DIR)

        # receive the directory structure and display it to the user
        print(recv_msg(conn))
      case Command.DELETE:
        # ask the user to enter the path of the file to be deleted
        file_path = input("File path: ")

        # send the delete request to the server
        send_message(conn, Command.DELETE, file_path)

        # display to the user whether the deletion was successful
        print(recv_msg(conn))
      case Command.SUBFOLDER:
        # ask the user for the subfolder action they wish to execute
        action: str = input('Create/Delete?: ').upper()

        # create a subfolder
        if action == 'CREATE':
          # ask the user for the parent directory and the name of the subfolder to be created
          file_path = input('Parent directory path: ')
          dir_name: str = input('New directory name: ')

          # send the subfolder creation request to the server
          send_message(conn, Command.SUBFOLDER, action, file_path, dir_name)
          print(recv_msg(conn))
          continue

        # delete a subfolder
        if action == 'DELETE':
          # ask the user for the path of the subfolder to be deleted
          file_path = input('Directory path to delete: ')

          # send the subfolder deletion request to the server
          send_message(conn, Command.SUBFOLDER, action, file_path)
          print(recv_msg(conn))
          continue

        # the subfolder action was not recognized
        print('Invalid subfolder action')
        continue
      case Command.DOWNLOAD:
        # ask the user to enter the path of the file they wish to download
        file_path = input('Specify the path of the file you want to download: ')

        # ask the user to select the location for the downloaded file to be saved to locally
        try:
          local_path: str = fd.askdirectory(title='Select a location to save the file')
        except FileNotFoundError:
          print('Download canceled')
          continue

        # send the download request to the server
        send_message(conn, Command.DOWNLOAD, file_path)

        # if the sever did denied the request, download canceled
        if not check_response_code(recv_msg(conn), Response.OK):
          continue

        send_message(conn, Response.ACK)

        # get the response code and actual message
        code, msg = get_code_and_msg(recv_msg(conn))

        # if the server encounter an issue
        if code != Response.OK:
          print('The server encountered an error')
          continue

        # extract the file length from the message
        file_length: int = int(msg)

        # file data received from the server
        file_data: bytes = b''

        # receive the file from the server
        while True:
          # status message
          print(f'{len(file_data)} / {file_length}: {len(file_data) / file_length * 100:.2f}% Complete...', end='\r')

          # receive data from the buffer
          file_data += conn.recv(file_length - len(file_data))

          # if all the file data has been received, stop waiting for more data
          if len(file_data) >= file_length:
            break

        print(f"{"File received":100}")

        # the local path of the file
        local_path = os.path.join(local_path, os.path.basename(file_path))

        # save the downloaded file
        with open(local_path, "wb") as file:
          file.write(file_data)

        print('File saved')

  # client disconnected from the server
  print('Disconnected from the server')
  conn.close()


if __name__ == "__main__":
  main()
