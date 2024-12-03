from enum import Enum
from socket import socket as Socket
from threading import Thread
import atexit
import base64
import bcrypt
import json
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


# get the IP address of the server
def get_ip() -> str:
  # create a socket and connect to a random address to get the server IP address (totally not sketchy)
  with Socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.connect(('10.0.0.0', 4500))

    # get the IP address the server connected to the random address with
    ip: str = s.getsockname()[0]

  return ip


IP: str = get_ip()
PORT: int = 4450
ADDR: tuple[str, int] = (IP, PORT)
SIZE: int = 1024
FORMAT: str = "utf-8"

DISALLOWED_CHARACTERS: list[str] = ['@', '|']
MAX_ALLOWED_LOGIN_ATTEMPTS: int = 3
SESSION_ID_LENGTH: int = 16 # bytes
WAIT_FOR_MSG_TIMEOUT: int = 10 # seconds
TIME_BETWEEN_STATUS_UPDATES: float = 0.5 # seconds

PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(512)

PROJECT_DATA_DIR: str = os.path.normpath('CNC_Project_Data')
FILE_STORAGE_DIR: str = os.path.join(PROJECT_DATA_DIR, 'File_Storage')
PASSWORDS_PATH: str = os.path.join(PROJECT_DATA_DIR, 'passwords.json')

server: Socket
all_connections: list[Socket] = []
logged_in_users: list[str] = []
files_being_processed: list[str] = []


# to handle the clients
def handle_client(conn: Socket, addr: tuple[str, int]) -> None:
  prefix = f"[{addr[0]}:{addr[1]}]:"

  print(f"{prefix} CONNECTED")
  send_message(conn, Response.OK, "Welcome to the server.")

  # generates a random session ID
  session_id: bytes = os.urandom(SESSION_ID_LENGTH)

  # send the client the session ID and the public key for password encryption
  conn.sendall(PUBLIC_KEY.save_pkcs1())
  wait_for_ack(conn)
  print(f"{prefix} Client recieved public key")

  conn.sendall(session_id)
  wait_for_ack(conn)
  print(f"{prefix} Client recieved session ID")

  cur_user: str | None = None
  num_login_attempts: int = 0

  while True:
    try:
      # receive messages from the client
      data: str | None = recv_msg(conn)
      print(data)

      # if the client closed the connection, close the connection on the server end
      if not data:
        print(f"{prefix} Client closed the connection")
        break

      # if the request does not contain an @ symbol
      if '@' not in data:
        print(f"{prefix} Message recieved is not properly formatted")
        send_message(conn, Response.BAD, "Request is not properly formatted.")
        continue

      # split the command and the data
      split_data: list[str] = data.split('@')
      received_cmd: str = split_data[0]
      data = split_data[1] if len(split_data) > 1 else None

      try:
        cmd: Command = Command(received_cmd)
      except ValueError:
        # not a valid command
        print(f"{prefix} The user entered an unrecognized command")
        send_message(conn, Response.BAD, "Command not recognized.")
        continue

      if cmd == Command.LOGIN:
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        # if the user is already logged in, tell them so
        if cur_user:
          print(f"{prefix} Attempted to login after previously logging in")
          send_message(conn, Response.REJECT, "You are already logged in.")
          continue

        num_login_attempts += 1

        # if the request does not contain the expected information
        split_data = data.split(' | ')
        if len(split_data) != 2:
          print(f"{prefix} Login request does not contain the required data")
          send_message(conn, Response.BAD, "Request does not contain the required data (username | encrypted data).")
          continue

        # pull out the information
        user: str = split_data[0]
        enc_data: str = split_data[1]

        # check if the credentials are valid
        valid: bool = validate_login_credentials(session_id, user, enc_data)

        # if the login credentials are valid
        if valid:
          # if the user is logged in on another device
          if user in logged_in_users:
            print(f"{prefix} User {user} tried to login while already being logged in on another device")
            send_message(conn, Response.REJECT, "You are already logged in on another device.")
            continue

          # log in the user
          cur_user = user
          logged_in_users.append(user)

          print(f"{prefix} {user} has logged in")
          send_message(conn, Response.OK, "Login successful.")

          prefix = cur_user + ':'
          continue

        # the login attempt failed
        print(f"{prefix} Failed login attempt")
        send_message(conn, Response.REJECT, "Incorrect username and password.")

        # if the user has not exceeded the maximum number of allowed login
        # attempts, continue accepting login attempts
        if num_login_attempts < MAX_ALLOWED_LOGIN_ATTEMPTS:
          continue

        # the user has exceeded the maximum number of allowed login attempts,
        # close the connection
        print(f"{prefix} Number of allowed login attempts exceeded")
        send_message(conn, Response.INFO, "Number of allowed login attempts exceeded.")
        break

      if cmd == Command.DISCONNECT:
        send_message(conn, Response.OK, "You have been disconnected.")

        # close the connection
        break

      # if the user is not logged in and is attempting to issue a command,
      # close the connection
      if not cur_user:
        print(f"{prefix} User attempted to issue a command without being logged in")
        send_message(conn, Response.UNAUTH, "Action not allowed. You are not logged in.")
        continue

      # user commands
      if cmd == Command.LOGOUT:
        print(f"{prefix} {cur_user} has been logged out")

        # logout the user
        logged_in_users.remove(cur_user)
        cur_user = None
        num_login_attempts = 0
        prefix = f"[{addr[0]}:{addr[1]}]:"

        send_message(conn, Response.OK, "You have been logged out successfully.")
        continue

      if cmd == Command.UPLOAD:
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        # if the request does not contain the expected information
        split_data = data.split(' | ')
        if len(split_data) != 3:
          print(f"{prefix} Upload request does not contain the required data")
          send_message(conn, Response.BAD, "Request does not contain the required data (directory path | file name).")
          continue

        # pull out the information
        dir_path: str = os.path.join(FILE_STORAGE_DIR, split_data[0])
        file_name: str = split_data[1]
        file_path: str = os.path.join(dir_path, file_name)
        file_length: int = int(split_data[2])

        # mark the file as being processed
        normal_file_path = os.path.normpath(file_path)
        files_being_processed.append(normal_file_path)

        # verify the path is valid
        if not verify_dir_exists(dir_path):
          print(f"{prefix} The file cannot be uploaded because the path \"{dir_path}\" does not exist")
          send_message(conn, Response.NOT_FOUND, "The specified directory does not exist.")

          # file processing completed
          files_being_processed.remove(normal_file_path)
          continue

        # receive the file
        print(f"{prefix} Receiving {file_name}...")
        send_message(conn, Response.OK, f"Send: {dir_path} {file_name}")
        wait_for_ack(conn)

        last_time: float = time.time() + TIME_BETWEEN_STATUS_UPDATES
        file_data: bytes = b''

        while True:
          if len(file_data) >= file_length:
            send_message(conn, Response.INFO, str(file_length))
            break

          print(f'{len(file_data)} / {file_length}: {len(file_data) / file_length * 100:.2f}% Complete...', end='\r')

          if time.time() - last_time >= TIME_BETWEEN_STATUS_UPDATES:
            send_message(conn, Response.INFO, str(len(file_data)))
            last_time = time.time()

          file_data += conn.recv(file_length - len(file_data))

        wait_for_ack(conn)

        # if the file already exists, ask the user to verify that they want to overwrite the file
        if not os.path.exists(file_path):
          print(f"{prefix} {file_name} Received")
          send_message(conn, Response.OK)
        else:
          print(f"{prefix} Uploading {file_path} will overwrite an existing file, asking user to verify")
          send_message(conn, Response.OVERWRITE, f"Uploading {file_path} will overwrite an existing file.")

          # wait for the user to respond to the overwrite verification request
          response: str | None = wait_for_msg(conn, Response.OVERWRITE, timeout=None)
          response = response[(response.index('@') + 1):] if response else ''
          confirmed_overwrite: bool = response == '1'

          # if the user did not confirm the overwrite
          if not confirmed_overwrite:
            # file processing completed
            files_being_processed.remove(normal_file_path)

            send_message(conn, Response.OK, "Upload canceled.")
            continue

          # if the file is already being used by another process
          print(files_being_processed.count(normal_file_path))
          if files_being_processed.count(normal_file_path) > 1:
            print(f"{prefix} Client tried to overwrite a file that's being used by another process")
            send_message(conn, Response.REJECT, f"Unable to overwrite, the specified file is being used by another process")

            # file processing completed
            files_being_processed.remove(normal_file_path)
            continue

          # acknowledge overwrite response
          send_message(conn, Response.OK, f"File being overwritten.")

        # create the file
        with open(file_path, 'wb') as file:
          file.write(file_data)

        # file processing completed
        files_being_processed.remove(normal_file_path)

        print(f"{prefix} Client successfully uploaded {file_path}")
        send_message(conn, Response.OK, "File uploaded successfully.")
        continue

      if cmd == Command.DOWNLOAD:
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        file_path = os.path.join(FILE_STORAGE_DIR, data)

        # mark the file as being processed
        normal_file_path = os.path.normpath(file_path)
        files_being_processed.append(normal_file_path)

        # verify the path is valid
        if not verify_file_exists(file_path):
          print(f"{prefix} {file_path} could not be found")
          send_message(conn, Response.NOT_FOUND, "The specified file could not be found.")

          # file processing completed
          files_being_processed.remove(normal_file_path)
          continue

        # send the client the length of the file
        file_length = os.path.getsize(normal_file_path)
        send_message(conn, Response.OK, str(file_length))
        wait_for_ack(conn)

        # send the file to the client
        with open(file_path, 'rb') as file:
          print(f"{prefix} Sending {file_path}...")

          conn.sendfile(file)

        # file processing completed
        files_being_processed.remove(normal_file_path)
        continue

      if cmd == Command.DELETE:
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        file_path = os.path.join(FILE_STORAGE_DIR, data)

        # verify the path is valid
        if not verify_file_exists(file_path):
          print(f"{prefix} {file_path} could not be found")
          send_message(conn, Response.NOT_FOUND, "The specified file could not be found.")
          continue

        # verify the file is not currently being used in another process
        if file_path in files_being_processed:
          print(f"{prefix} {file_path} could not be deleted because it is being used by another process")
          send_message(conn, Response.REJECT, "The specified file is currently being used by another process.")
          continue

        # delete the file
        print(f"{prefix} Deleting {file_path}...")
        os.remove(file_path)
        print(f"{prefix} {file_path} Deleted successfully")
        send_message(conn, Response.OK)
        continue

      if cmd == Command.DIR:
        # get the formatted directory structure
        structure: str = get_directory_structure(FILE_STORAGE_DIR)

        print(f"{prefix} Requested directory structure")
        send_message(conn, Response.OK, structure)
        continue

      if cmd == Command.SUBFOLDER:
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        # if the request does not contain the expected information
        split_data = data.split(' | ')
        if len(split_data) < 2:
          print(f"{prefix} Subfolder request does not contain the required data")
          send_message(conn, Response.BAD, "Request does not contain the required data.")
          continue

        # pull out the information
        action: str = split_data[0].upper()

        if action == "CREATE":
          # if the request does not contain the expected information
          if len(split_data) != 3:
            print(f"{prefix} Subfolder create request does not contain the required data")
            send_message(conn, Response.BAD, "Request does not contain the required data (CREATE | parent path | directory name).")
            continue

          # pull out the information
          parent_path: str = os.path.normpath(os.path.join(FILE_STORAGE_DIR, split_data[1]) if split_data[1] else FILE_STORAGE_DIR)
          dir_name: str = split_data[2]
          full_path: str = os.path.join(parent_path, dir_name)
          print(f'Parent path: {parent_path}')
          print(f'Directory name: {dir_name}')
          print(f'Full path: {full_path}')

          # verify the path is valid
          if not verify_potential_dir_path(parent_path):
            print(f"{prefix} The parent folder {parent_path} could not be found")
            send_message(conn, Response.NOT_FOUND, f"The parent folder {parent_path} could not be found.")
            continue


          # if the subdirectory already exists, tell the client the subdirectory can't be created
          if os.path.exists(full_path):
            print(f"{prefix} The subdirectory could not be created because it already exists")
            send_message(conn, Response.REJECT, f"The subdirectory {full_path} already exists.")
            continue

          # make the subdirectory
          os.mkdir(full_path)
          print(f"{prefix} A subdirectory {full_path} was created")
          send_message(conn, Response.OK, f"Subdirectory {full_path} was created.")
          continue
        elif action == "DELETE":
          # if the request does not contain the expected information
          if len(split_data) != 2:
            print(f"{prefix} Subfolder delete request does not contain the required data")
            send_message(conn, Response.BAD, "Request does not contain the required data (DELETE | directory path).")
            continue

          # pull out the information
          path: str = os.path.join(FILE_STORAGE_DIR, split_data[1])

          # verify the path is valid
          if not verify_dir_exists(path):
            print(f"{prefix} The subdirectory {path} could not be found")
            send_message(conn, Response.NOT_FOUND, f"The subdirectory {path} could not be found.")
            continue

          # if the path is the file storage directory, it cannot be deleted
          if os.path.samefile(path, FILE_STORAGE_DIR):
            print(f"{prefix} Client tried to delete the file storage directory")
            send_message(conn, Response.FORBID, "You cannot delete the file storage directory.")
            continue

          # if the directory contains files, it cannot be deleted
          if any(os.scandir(path)):
            print(f"{prefix} Client tried to delete a subdirectory that contains other files/directories")
            send_message(conn, Response.REJECT, "The subdirectory could not be deleted because there are files/directories under it.")
            continue

          # delete the file
          os.rmdir(path)
          print(f"{prefix} A subdirectory {path} was deleted")
          send_message(conn, Response.OK, f"Subdirectory {path} was deleted.")
          continue
        else:
          # tell the client the action is not recognized
          print(f"{prefix} Subfolder action not recognized")
          send_message(conn, Response.BAD, "The subfolder is not recognized.")
          continue

      # not a valid command
      print(f"{prefix} The user entered an unrecognized command")
      send_message(conn, Response.BAD, "Command not recognized.")
    except TimeoutError as e:
      print()
      send_message(conn, Response.REJECT, e.args[0])
      break
    except OSError:
      print(f"{prefix} The client connection was closed")
      break
    except Exception as e:
      # display error message
      print(e)
      print(f"{prefix} The server encountered an error while processing a client message...")
      send_message(conn, Response.BAD, "Unable to process message.")

  # logout the user
  if cur_user:
    logged_in_users.remove(cur_user)

  # close the connection
  print(f"{prefix} Disconnected")
  all_connections.remove(conn)
  conn.close()


# send the given message and response code through the client connection
def send_message(conn: Socket, code: Response, *msg: str) -> None:
  message: str = f'{code.value}@{' | '.join(msg)}'
  print(f"--Sending: {message}")
  conn.sendall(message.encode(FORMAT))


# receive a message from the given client connection
def recv_msg(conn: Socket, size: int=SIZE) -> str:
  return conn.recv(size).decode(FORMAT)


# return the code and actual message extracted from the message
def get_code_and_msg(msg: str) -> tuple[Response, str]:
  parts: list[str] = msg.split('@')
  return (Response(parts[0]), parts[1] if len(parts) == 2 else '')


# return the actual message in the message (without the response code)
def get_msg(msg: str) -> str:
  return msg.split('@')[1]


# check if the given message starts with the given response code
def check_response_code(msg: str, code: Response) -> bool:
  return msg.startswith(code.value + '@')


# wait for the client to send an acknowledgement
def wait_for_ack(conn: Socket) -> str:
  return wait_for_msg(conn, Response.ACK)


# wait for the client to send a message with the given response code
def wait_for_msg(conn: Socket, code: Response, *, timeout: int | None=WAIT_FOR_MSG_TIMEOUT) -> str:
  # set the connection to timeout after a set number of seconds
  conn.settimeout(timeout)

  try:
    # wait for the message
    data: str = ''

    while not check_response_code(data, code):
      data = recv_msg(conn)

    return data
  except TimeoutError:
    print("Client failed to respond and timed out")
    raise TimeoutError('Did not receive acknowledgement from the client')
  finally:
    # set the connection to not timeout
    conn.settimeout(None)


# check if the given username, password, and session ID are valid
def validate_login_credentials(session_id_actual: bytes, user: str, enc_data: str) -> bool:
  # decrypt the pasword and session ID
  data: bytes = base64.b64decode(enc_data.encode(FORMAT))
  data = rsa.decrypt(data, PRIVATE_KEY)
  pwd: bytes = data[:-SESSION_ID_LENGTH]
  session_id_received: bytes = data[-SESSION_ID_LENGTH:]

  # if the session ID does not match, the credentials are not valid
  if session_id_actual != session_id_received:
    return False

  # open the passwords file
  try:
    with open(PASSWORDS_PATH, 'r') as file:
      # get all the user credentials
      all_credentials: dict[str, str] = json.load(file)
  except FileNotFoundError:
    return False

  # if the username is not in the list of credentials, the user's credentials are not valid
  if user not in all_credentials:
    return False

  # get the hashed password for the user
  hash: bytes = all_credentials[user].encode(FORMAT)

  # clear the credentials out of the memory
  all_credentials.clear()

  # return if the password matches the hashed password and therefore the credentials are valid
  return bcrypt.checkpw(pwd, hash)


# verify that a file exists at the given file path
def verify_file_exists(path: str) -> bool:
  return os.path.exists(path) and os.path.isfile(path) and verify_in_storage_dir(path)


# verify that a directory exists at the given file path
def verify_dir_exists(path: str) -> bool:
  return os.path.exists(path) and os.path.isdir(path) and verify_in_storage_dir(path)


# verify that a potential path for a file is valid
def verify_potential_file_path(path: str) -> bool:
  return os.path.isfile(path) and verify_in_storage_dir(path) and os.path.exists(os.path.dirname(path))


# verify that a potential path for a directory is valid
def verify_potential_dir_path(path: str) -> bool:
  return os.path.isdir(path) and verify_in_storage_dir(path) and os.path.exists(path)


# verify that a path for a file or directory is in the project storage directory
def verify_in_storage_dir(path: str) -> bool:
  return os.path.normpath(path).startswith(FILE_STORAGE_DIR)

# returns a string containing the directory structure for the given path
def get_directory_structure(path: str, indent_lvl: int=0) -> str:
  structure: str = ''

  for entry in os.scandir(path):
    if os.path.isdir(entry):
      structure += '    ' * indent_lvl + f"DIR: {entry.name}\n"
      structure += get_directory_structure(entry.path, indent_lvl + 1)
    else:
      structure += '    ' * indent_lvl + f"FILE: {entry.name}\n"

  return structure


# handle the input from the command line interface
def handle_cli() -> None:
  time.sleep(0.1)

  prefix: str = "[CLI]:"

  print(f"\n{prefix} Enter 'HELP' for a list of commands.")

  while True:
    # get the command input from the CLI
    cmd: str = input().upper()

    if cmd == "ADD LOGIN":
      # get the new username from the CLI
      user: str = input(f"{prefix} Enter the new username: ")

      # if no username was entered, the process was canceled
      if not user:
        print(f"{prefix} Add login canceled\n")
        continue

      # if the username already exists, cancel the process
      try:
        with open(PASSWORDS_PATH, 'r') as file:
          if user in json.load(file):
            print(f"{prefix} That username already exists")
            print(f"{prefix} Add login canceled\n")
            continue
      except FileNotFoundError:
        pass

      # get the new password from the CLI
      pwd: str = input(f"{prefix} Enter the new password: ")

      # if no password was entered, the process was canceled
      if not pwd:
        print(f"{prefix} Add login canceled\n")
        continue

      # if the password contains disallowed characters, the process is canceled
      bad_pwd: bool = False
      for c in DISALLOWED_CHARACTERS:
        if c in pwd:
          bad_pwd = True
          break

      if bad_pwd:
        print(f"{prefix} The entered password contains one or more disallowed characters")
        print(f"{prefix} Add login canceled\n")
        continue

      # salt and hash the password
      salt: bytes = bcrypt.gensalt()
      hash: str = bcrypt.hashpw(bytes(pwd, FORMAT), salt).decode(FORMAT)

      # save the username and the hashed password in the passwords file
      new_login: dict[str, str] = {user: hash}

      try:
        with open(PASSWORDS_PATH, 'r') as file:
          pwds: dict[str, str] = json.load(file)
          pwds.update(new_login)
      except FileNotFoundError:
        pwds = new_login

      with open(PASSWORDS_PATH, 'w') as file:
        json.dump(pwds, file)

      print(f"{prefix} Login added successfully\n")
      continue

    if cmd == "SHUTDOWN":
      print(f"{prefix} Shutdown called")
      return

    if cmd == "HELP":
      space: int = 10
      print('',
            f'{'ADD LOGIN':{space}}- Add a user login',
            f'{'SHUTDOWN':{space}}- Shutdown the server',
            '',
            sep='\n'
            )
      continue

    print(f"{prefix} Command not recognized")


# accept all incoming connections and handle them on separate threads
def accept_connections() -> None:
  # open a socket and listen for client connections
  global server
  server = Socket(socket.AF_INET, socket.SOCK_STREAM) # uses IPV4 and TCP connection

  # try binding on different ports until an open one is found
  global ADDR, PORT
  while True:
    try:
      server.bind(ADDR) # bind the address
    except OSError:
      print(f'Unable to bind to port {PORT}')

      # go to the next port
      PORT += 1
      ADDR = (IP, PORT)
      continue
    break

  server.listen() # start listening

  print(f"Server is listening on {IP}:{PORT}")

  # wait for client connections
  try:
    while True:
      # accept client connection
      conn, addr = server.accept() # accept a connection from a client
      all_connections.append(conn)

      # handle client requests on a separate thread
      thread: Thread = Thread(target=handle_client, args=(conn, addr)) # assigning a thread for each client
      thread.start()
  except:
    print("Server interrupted")


def main() -> None:
  print("Starting the server")

  # if the project data directory does not exists, create it
  if not os.path.exists(PROJECT_DATA_DIR):
    print("Created project data directory")
    os.mkdir(PROJECT_DATA_DIR)

  # if the file storage directory does not exists, create it
  if not os.path.exists(FILE_STORAGE_DIR):
    print("Created storage directory")
    os.mkdir(FILE_STORAGE_DIR)

  # handle the CLI on a separate thread
  cli_thread: Thread = Thread(target=handle_cli)
  cli_thread.start()

  # handle accepting client connections on a separate thread
  accept_connections_thread: Thread = Thread(target=accept_connections)
  accept_connections_thread.start()

  # while the CLI and accept connections threads are still alive, keep the server running
  while cli_thread.is_alive() and accept_connections_thread.is_alive():
    pass

  print("Shutting down server...")

  # close the server and client sockets
  server.close()
  for conn in all_connections:
    conn.close()

  # timeout the CLI and accept connections threads
  cli_thread.join(timeout=0)
  accept_connections_thread.join(timeout=0)

# print a message when the program ends
@atexit.register
def exit_handler() -> None:
  print("Server shutdown complete.")


if __name__ == "__main__":
  main()
