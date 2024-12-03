from enum import Enum
from socket import socket as Socket
from threading import Thread
from tkinter import filedialog as fd
import base64
import os
import re
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
  HELP = 'HELP'


PORT = 4450
SIZE: int = 1024  # bytes
FORMAT: str = "utf-8"

IP_REGEX: re.Pattern = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')
MAX_CONNECTION_REQUESTS: int = 50


# recieve upload status messages from the server
def receive_status_msgs(conn: Socket, length_to_send: int):
  length_received: int = 0

  # receive updates while the server still hasn't received all the data
  while True:
    # receive a status update on the upload from the server
    length_received = int(get_msg(recv_msg(conn)))

    # if the server has received all the data, stop waiting for status updates
    if length_received >= length_to_send:
      break

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
  return get_code_and_msg(msg)[1]


# receive a string message from the server
def recv_msg(conn: Socket, size: int=SIZE) -> str:
  # wait for a message from the server
  msg = conn.recv(size).decode(FORMAT)

  # if the message is empty it means the server has closed the connection
  if not msg:
    raise ConnectionAbortedError('The server terminated the connection')

  return msg


def main() -> None:
  print()

  # get the server IP address from the user
  while True:
    IP: str = input('Enter the server IP address: ')

    # if the user input is a valid IP address, move on
    if re.search(IP_REGEX, IP):
      break

    print('Invalid IP address, try again...')

  # server address
  global PORT
  ADDR: tuple[str, int] = (IP, PORT)

  connection_attempts: int = 0
  print()

  # attempt connecting to the server on different ports until the port the server is on is found
  while True:
    connection_attempts += 1

    try:
      # connect to the server
      conn: Socket = Socket(socket.AF_INET, socket.SOCK_STREAM)
      conn.connect(ADDR)
    except OSError:
      print(f'Could not connect to the server on port {PORT}')

      # if the number of connection attempts has been exceeded, the server could not be found
      if connection_attempts >= MAX_CONNECTION_REQUESTS:
        print(f"Server could not be found")
        return

      # go to the next port
      PORT += 1
      ADDR = (IP, PORT)
      continue
    break

  print(f'Connecting to server at {IP}:{PORT}...')

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

  # whether the user is currently logged in
  logged_in: bool = False

  # print initial help message
  print("\nEnter 'HELP' for a list of commands.", end='')

  # accept user commands
  while True:
    # get the command the user wants to enter
    entered_cmd: str = input("\nEnter a command: ").upper()

    # check if the command the user entered is valid
    try:
      cmd: Command = Command(entered_cmd)
    except ValueError:
      print('Command not recognized')
      continue

    # execute the functionality for the command the user entered
    match cmd:
      case Command.UPLOAD:
        # if the user is not logged in, they cannot run this command
        if not logged_in:
          print('You are not logged into the server')
          continue

        # ask the user to select a file to upload to the server
        file_path: str = fd.askopenfilename(title="Select a file to upload")

        # if the user didn't select a file
        if not file_path:
          print('Upload canceled')
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
        time.sleep(0.1)

        # send the file
        with open(file_path, 'rb') as file:
          conn.sendfile(file)

        # wait for the status messages to finish printing
        status_thread.join()

        # receive the server's response to the upload
        response = conn.recv(SIZE).decode(FORMAT)
        print(response)

        # if the file doesn't need to be overwritten
        if not check_response_code(response, Response.OVERWRITE):
          print(recv_msg(conn))
          continue

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
        # if the user is already logged in, they cannot run this command
        if logged_in:
          print('You are already logged into the server')
          continue

        # get the username and password from the user
        user: str = input("Username: ")
        pwd: str = input("Password: ")

        # combine the password and session ID, encrypt the data, and base64 encode the data
        pwd_sid: bytes = pwd.encode(FORMAT) + session_id
        enc_data: bytes = rsa.encrypt(pwd_sid, key)
        encoded_data: str = base64.b64encode(enc_data).decode(FORMAT)

        # send the user's credentials to the server
        send_message(conn, Command.LOGIN, user, encoded_data)

        response = recv_msg(conn)

        if check_response_code(response, Response.OK):
          print('You have been logged in successfully')
          logged_in = True
          continue

        print('Login Failed: Invalid username and/or password.')
      case Command.LOGOUT:
        # if the user is not logged in, they cannot run this command
        if not logged_in:
          print('You are not logged into the server')
          continue

        # request the server to logout the user
        send_message(conn, Command.LOGOUT)

        # get the server's response
        response = recv_msg(conn)

        # if the sever did not say the logout was successful, something went wrong
        if not check_response_code(response, Response.OK):
          print('Logout Failed')
          continue

        # the user has been logged out successfully
        logged_in = False
        print('You have been logged out successfully')
      case Command.DISCONNECT:
        # send the disconnect request to the server
        send_message(conn, Command.DISCONNECT)

        # disconnect
        break
      case Command.DIR:
        # if the user is not logged in, they cannot run this command
        if not logged_in:
          print('You are not logged into the server')
          continue

        # ask the server for the file storage directory structure
        send_message(conn, Command.DIR)

        # receive the directory structure and display it to the user
        print(recv_msg(conn))
      case Command.DELETE:
        # if the user is not logged in, they cannot run this command
        if not logged_in:
          print('You are not logged into the server')
          continue

        # ask the user to enter the path of the file to be deleted
        file_path = input("File path: ")

        # send the delete request to the server
        send_message(conn, Command.DELETE, file_path)

        # display to the user whether the deletion was successful
        print(get_msg(recv_msg(conn)))
      case Command.SUBFOLDER:
        # if the user is not logged in, they cannot run this command
        if not logged_in:
          print('You are not logged into the server')
          continue

        # ask the user for the subfolder action they wish to execute
        action: str = input('Create/Delete?: ').upper()

        # create a subfolder
        if action == 'CREATE':
          # ask the user for the parent directory and the name of the subfolder to be created
          file_path = input('Parent directory path: ')
          dir_name: str = input('New directory name: ')

          # send the subfolder creation request to the server
          send_message(conn, Command.SUBFOLDER, action, file_path, dir_name)
          print(get_msg(recv_msg(conn)))
          continue

        # delete a subfolder
        if action == 'DELETE':
          # ask the user for the path of the subfolder to be deleted
          file_path = input('Directory path to delete: ')

          # send the subfolder deletion request to the server
          send_message(conn, Command.SUBFOLDER, action, file_path)
          print(get_msg(recv_msg(conn)))
          continue

        # the subfolder action was not recognized
        print('Invalid subfolder action')
        continue
      case Command.DOWNLOAD:
        # if the user is not logged in, they cannot run this command
        if not logged_in:
          print('You are not logged into the server')
          continue

        # ask the user to enter the path of the file they wish to download
        file_path = input('Specify the path of the file you want to download: ')

        # ask the user to select the location for the downloaded file to be saved to locally
        local_path: str = fd.askdirectory(title='Select a location to save the file')

        # if the user did not select a directory
        if not local_path:
          print('Download canceled')
          continue

        # send the download request to the server
        send_message(conn, Command.DOWNLOAD, file_path)

        # get the server's response
        response = recv_msg(conn)

        # if the sever denied the request, download canceled
        if not check_response_code(response, Response.OK):
          print(get_msg(response))
          continue

        send_message(conn, Response.ACK)

        # get the response code and actual message
        code, msg = get_code_and_msg(response)

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
          # if all the file data has been received, stop waiting for more data
          if len(file_data) >= file_length:
            break

          # status message
          print(f'{len(file_data)} / {file_length}: {len(file_data) / file_length * 100:.2f}% Complete...', end='\r')

          # receive data from the buffer
          file_data += conn.recv(file_length - len(file_data))

        print(f"{"File received":100}")

        # the local path of the file
        local_path = os.path.join(local_path, os.path.basename(file_path))

        # save the downloaded file
        with open(local_path, "wb") as file:
          file.write(file_data)

        print('File saved')
      case Command.HELP:
        # print all the commands the user can enter
        space: int = 12
        print('',
              f'{'LOGIN':{space}}- Login to the server',
              f'{'LOGOUT':{space}}- Logout of the server',
              f'{'DISCONNECT':{space}}- Disconnect from the server',
              f'{'UPLOAD':{space}}- Upload a file to the server',
              f'{'DOWNLOAD':{space}}- Download a file from the server',
              f"{'DIR':{space}}- Display the server's file directory",
              f'{'DELETE':{space}}- Delete a file from the server',
              f'{'SUBFOLDER':{space}}- Create or delete a subfolder from the server',
              sep='\n'
              )

  # client disconnected from the server
  print('Disconnected from the server')
  conn.close()


if __name__ == "__main__":
  main()
