from enum import Enum
import bcrypt
import json
import os
import rsa
import socket
import threading


# response codes
class Response(Enum):
  OK = "OK" # request successful
  END = "END" # file transmission is done
  INFO = "INFO" # unsolicited information
  OVERWRITE = "VERIFY_OVERWRITE" # asks the client to verify that they want a file to be overwritten
  KEY = "KEY" # contains a public key
  BAD = "BAD_REQUEST" # bad syntax
  UNAUTH = "UNAUTHORIZED" # not logged in
  FORBID = "FORBIDDEN" # not allowed (after log in)
  NOT_FOUND = "NOT_FOUND" # file or directory not found
  REJECT = "REJECTED" # the request is recognized and properly formatted but was rejected


# get the IP address of the server
def get_ip():
  # create a socket and connect to a random address (totally not sketchy)
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(('10.0.0.0', 4500))

  # get the IP address the server connected to the random address with
  ip = s.getsockname()[0]

  # close the socket
  s.close()

  return ip


IP = get_ip()
PORT = 4453
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"

DISALLOWED_CHARACTERS = ['@', '|']
MAX_ALLOWED_LOGIN_ATTEMPTS = 3
SESSION_ID_LENGTH = 16 # bytes

PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(512)

PROJECT_DATA_DIR = os.path.normpath('CNC_Project_Data')
FILE_STORAGE_DIR = os.path.join(PROJECT_DATA_DIR, 'File_Storage')
PASSWORDS_PATH = os.path.join(PROJECT_DATA_DIR, 'passwords.json')

shutdown = False
files_being_processed = list()
waiting_overwrites = {}


# to handle the clients
def handle_client(conn, addr):
  prefix = f"[{addr[0]}]:"

  print(f"{prefix} CONNECTED")
  send_message(conn, Response.OK, "Welcome to the server.")

  # generates a random session ID
  session_id = os.urandom(SESSION_ID_LENGTH)

  # send the client the session ID and the public key for password encryption
  conn.sendall(PUBLIC_KEY.save_pkcs1())
  wait_for_ack(conn)
  print(f"{prefix} Client recieved public key")

  conn.sendall(bytes(session_id))
  wait_for_ack(conn)
  print(f"{prefix} Client recieved session ID")

  cur_user = None
  num_login_attempts = 0

  # remove later!!!!!!!!!!!!
  cur_user = 'test'

  while True:
    # if the server is commanded to shutdown, close the connection
    if shutdown:
      break

    try:
      # receive messages from the client
      data = conn.recv(SIZE).decode(FORMAT)
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
      data = data.split('@')
      cmd = data[0]
      data = data[1] if len(data) > 1 else None

      if cmd == "LOGIN":
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
        data = data.split(' | ')
        if len(data) != 2:
          print(f"{prefix} Login request does not contain the required data")
          send_message(conn, Response.BAD, "Request does not contain the required data (username | encrypted data).")
          continue

        # pull out the information
        user = data[0]
        enc_data = data[1]

        # check if the credentials are valid
        valid = validate_login_credentials(session_id, user, enc_data)

        # if the login credentials are valid, log in the user
        if valid:
          cur_user = user

          print(f"{prefix} {user} has logged in")
          send_message(conn, Response.OK, "Login successful.")
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

      if cmd == "DISCONNECT":
        # close the connection
        break

      # if the user is not logged in and is attempting to issue a command,
      # close the connection
      if not cur_user:
        print(f"{prefix} User attempted to issue a command without being logged in")
        send_message(conn, Response.UNAUTH, "Action not allowed. You are not logged in.")
        continue

      # user commands
      if cmd == "LOGOUT":
        print(f"{prefix} {cur_user} has been logged out")

        cur_user = None
        num_login_attempts = 0

        send_message(conn, Response.OK, "You have been logged out successfully.")
        continue

      if cmd == "UPLOAD":
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        # if the request does not contain the expected information
        data = data.split(' | ')
        if len(data) != 2:
          print(f"{prefix} Upload request does not contain the required data")
          send_message(conn, Response.BAD, "Request does not contain the required data (directory path | file name).")
          continue

        # pull out the information
        dir_path = data[0]
        file_name = data[1]
        file_path = os.path.join(dir_path, file_name)

        # mark the file as being processed
        normal_file_path = os.path.normpath(file_path)
        files_being_processed.append(normal_file_path)

        # verify the path is valid
        if not verify_path(dir_path, True, False):
          print(f"{prefix} The file cannot be uploaded because the path \"{dir_path}\" does not exist")
          send_message(conn, Response.NOT_FOUND, "The specified directory does not exist.")

          # file processing completed
          files_being_processed.remove(normal_file_path)
          continue

        # receive the file
        print(f"{prefix} Receiving {file_name}...")
        send_message(conn, Response.OK, f"Send: {dir_path} {file_name}")

        file_data = b''
        while True:
          received_data = conn.recv(SIZE)

          if received_data.decode(FORMAT).split('@')[0] == Response.END:
            print(f"{prefix} {file_name} Received")
            send_message(conn, Response.OK)
            break

          file_data += received_data

        # if the file already exists, ask the user to verify that they want to overwrite the file
        if os.path.exists(dir_path):
          print(f"{prefix} Uploading {file_path} will overwrite an existing file, asking user to verify")
          send_message(conn, Response.VERIFY, f"Uploading {file_path} will overwrite an existing file.")

          # file processing completed
          files_being_processed.remove(normal_file_path)

          # add the file to the list of files waiting to be overridden
          waiting_overwrites[addr] = {'path': file_path, 'data': file_data}
          continue

        # create the file
        with open(file_path, 'wb') as file:
          file.write(file_data)

        # file processing completed
        files_being_processed.remove(normal_file_path)
        continue

      if cmd == "DOWNLOAD":
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        file_path = data

        # mark the file as being processed
        normal_file_path = os.path.normpath(file_path)
        files_being_processed.append(normal_file_path)

        # verify the path is valid
        if not verify_path(file_path, False, True):
          print(f"{prefix} {file_path} could not be found")
          send_message(conn, Response.NOT_FOUND, "The specified file could not be found.")

          # file processing completed
          files_being_processed.remove(normal_file_path)
          continue

        # send the file to the client
        with open(file_path, 'rb') as file:
          print(f"{prefix} Sending {file_path}...")

          socket.sendfile(file)

          print(f"{prefix} File transmission for {file_path} complete")
          send_message(conn, Response.END, f"{file_path}")

        # file processing completed
        files_being_processed.remove(normal_file_path)
        continue

      if cmd == "DELETE":
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        file_path = os.path.join(FILE_STORAGE_DIR, data)

        # verify the path is valid
        if not verify_path(file_path, False, True):
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

      if cmd == "DIR":
        # get the formatted directory structure
        structure = get_directory_structure(FILE_STORAGE_DIR)

        print(f"{prefix} Requested directory structure")
        send_message(conn, Response.OK, structure)
        continue

      if cmd == "SUBFOLDER":
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        # if the request does not contain the expected information
        data = data.split(' | ')
        if len(data) < 2:
          print(f"{prefix} Subfolder request does not contain the required data")
          send_message(conn, Response.BAD, "Request does not contain the required data.")
          continue

        # pull out the information
        action = data[0].upper()

        if action == "CREATE":
          # if the request does not contain the expected information
          if len(data) != 3:
            print(f"{prefix} Subfolder create request does not contain the required data")
            send_message(conn, Response.BAD, "Request does not contain the required data (CREATE | parent path | directory name).")
            continue

          # pull out the information
          parent_path = os.path.join(FILE_STORAGE_DIR, data[1])
          dir_name = data[2]

          # verify the path is valid
          if not verify_path(parent_path, True, False):
            print(f"{prefix} The parent folder {parent_path} could not be found")
            send_message(conn, Response.NOT_FOUND, f"The parent folder {parent_path} could not be found.")
            continue

          full_path = os.path.join(parent_path, dir_name)

          # if the subdirectory already exists, tell the client the subdirectory can't be created
          if os.path.exists(full_path):
            print(f"{prefix} The subdirectory could not be created because it already exists")
            send_message(conn, Response.REJECT, f"The subdirectory {full_path} already exists.")

          # make the subdirectory
          os.mkdir(full_path)
          print(f"{prefix} A subdirectory {full_path} was created")
          send_message(conn, Response.OK, f"Subdirectory {full_path} was created.")
          continue
        elif action == "DELETE":
          # if the request does not contain the expected information
          if len(data) != 2:
            print(f"{prefix} Subfolder delete request does not contain the required data")
            send_message(conn, Response.BAD, "Request does not contain the required data (DELETE | directory path).")
            continue

          # pull out the information
          path = os.path.join(FILE_STORAGE_DIR, data[1])

          # verify the path is valid
          if not verify_path(path, True, True):
            print(f"{prefix} The subdirectory {path} could not be found")
            send_message(conn, Response.NOT_FOUND, f"The subdirectory {path} could not be found.")
            continue

          # if the path is the file storage directory, it cannot be deleted
          if os.path.samefile(path, FILE_STORAGE_DIR):
            print(f"{prefix} Client tried to delete the file storage directory")
            send_message(conn, Response.FORBID, "You cannot delete the file storage directory.")
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

      if cmd == "OVERWRITE":
        # if there is no data
        if not data:
          print(f"{prefix} Message recieved contains no data")
          send_message(conn, Response.BAD, "Request contains no data.")
          continue

        if not data.isdigit():
          print(f"{prefix} Overwrite response not recognized")
          send_message(conn, Response.BAD, "Overwrite response not recognized.")
          continue

        if addr not in waiting_overwrites:
          print(f"{prefix} The user tried to respond to an overwrite request that doesn't exist")
          send_message(conn, Response.BAD, "There is no pending file overwrite request.")
          continue

        # get the file path and data from the overwrite list
        file_path = waiting_overwrites[addr]['path']
        file_data = waiting_overwrites[addr]['data']

        # verify the file is not currently being used in another process
        if file_path in files_being_processed:
          # remove the file data from the overwrite list
          del waiting_overwrites[addr]

          print(f"{prefix} {file_path} could not be overwritten because it is being used by another process")
          send_message(conn, Response.REJECT, "The specified file is currently being used by another process.")
          continue

        match int(data):
          case 1:
            # mark the file as being processed
            normal_file_path = os.path.normpath(file_path)
            files_being_processed.append(normal_file_path)

            # create the file
            with open(file_path, 'wb') as file:
              file.write(file_data)

            # file processing completed
            files_being_processed.remove(normal_file_path)

            # remove the file data from the overwrite list
            del waiting_overwrites[addr]

            print(f"{prefix} overwrite accepted for {file_path}")
            send_message(conn, Response.OK)
          case 0:
            # remove the file from the overwrite list
            del waiting_overwrites[addr]

            print(f"{prefix} overwrite declined for {file_path}")
            send_message(conn, Response.OK)
          case _:
            print(f"{prefix} Overwrite response not recognized")
            send_message(conn, Response.BAD, "Overwrite response not recognized.")

        continue

      # not a valid command
      print(f"{prefix} The user entered an unrecognized command")
      send_message(conn, Response.BAD, "Command not recognized.")
    except Exception as e:
      # display error message
      print(e)
      print(f"{prefix} The server encountered an error while processing a client message...")
      send_message(conn, Response.BAD, "Unable to process message.")

  # if there is an overwrite request waiting, cancel it
  if addr in waiting_overwrites:
    del waiting_overwrites[addr]

  # close the connection
  print(f"{prefix} Disconnected")
  conn.close()


# send the given message and response code through the client connection
def send_message(conn, code, msg=''):
  print(f"Sending: {code.value}@{msg}")
  conn.sendall(f"{code.value}@{msg}".encode(FORMAT))

# wait for the client to send an acknowledgement
def wait_for_ack(conn):
  data = None
  while data != "ACK@":
    data = conn.recv(SIZE).decode(FORMAT)


# check if the given username, password, and session ID are valid
def validate_login_credentials(session_id_actual, user, enc_data):
  # decrypt the pasword and session ID
  data = rsa.decrypt(enc_data, PRIVATE_KEY).decode(FORMAT)
  pwd = data[:-SESSION_ID_LENGTH]
  session_id_received = data[-SESSION_ID_LENGTH:]

  # if the session ID does not match, the credentials are not valid
  if session_id_actual != session_id_received:
    return False

  # open the passwords file
  try:
    with open(PASSWORDS_PATH, 'r') as file:
      # get all the user credentials
      all_credentials = json.load(file)
  except FileNotFoundError:
    return False

  # if the username is not in the list of credentials, the user's credentials are not valid
  if user not in all_credentials:
    return False

  # get the user's salt and hashed password
  data = all_credentials[user]
  hash_actual = data['hash']
  salt = data['salt']

  # clear the credentials out of the memory
  all_credentials.clear()

  # salt and hash the entered password
  hash_received = bcrypt.hashpw(pwd.encode(FORMAT), salt.encode(FORMAT)).decode(FORMAT)

  # return if the hashes match and therefore the credentials are valid
  return hash_actual == hash_received


# verify that the given path is valid and within the folder structure
def verify_path(path, is_directory, must_exist):
  # if the path is supposed to exist, but it does not, the path is not valid
  if must_exist and not os.path.exists(path):
    return False

  # if the path is supposed to be for a directory, but it isn't, the path is
  # not valid
  if is_directory and not os.path.isdir(path):
    return False

  # if the path is somewhere in the file storage directory, it is valid
  path = os.path.normpath(path)
  return path.startswith(FILE_STORAGE_DIR)

# returns a string containing the directory structure for the given path
def get_directory_structure(path, indent_lvl=0):
  structure = ''

  for entry in os.scandir(path):
    if os.path.isdir(entry):
      structure += '|    ' * indent_lvl + f"DIR: {entry.name}\n"
      structure += get_directory_structure(entry.path, indent_lvl + 1)
    else:
      structure += '|    ' * indent_lvl + f"FILE: {entry.name}\n"

  return structure

# handle the input from the command line interface
def handle_cli():
  prefix = "[CLI]:"

  while True:
    # get the command input from the CLI
    cmd = input().upper()

    if cmd == "ADD LOGIN":
      # get the new username from the CLI
      user = input(f"{prefix} Enter the new username: ")

      # if no username was entered, the process was canceled
      if not user:
        print(f"{prefix} Add login canceled")
        continue

      # if the username already exists, cancel the process
      try:
        with open(PASSWORDS_PATH, 'r') as file:
          if user in json.load(file):
            print(f"{prefix} That username already exists")
            print(f"{prefix} Add login canceled")
            continue
      except FileNotFoundError:
        pass

      # get the new password from the CLI
      pwd = input(f"{prefix} Enter the new password: ")

      # if no password was entered, the process was canceled
      if not pwd:
        print(f"{prefix} Add login canceled")
        continue

      # if the password contains disallowed characters, the process is canceled
      bad_pwd = False
      for c in DISALLOWED_CHARACTERS:
        if c in pwd:
          bad_pwd = True
          break

      if bad_pwd:
        print(f"{prefix} The entered password contains one or more disallowed characters")
        print(f"{prefix} Add login canceled")
        continue

      # salt and hash the password
      salt = bcrypt.gensalt()
      hashed = bcrypt.hashpw(bytes(pwd, FORMAT), salt).decode(FORMAT)
      salt = salt.decode(FORMAT)

      # save the username, hashed password, and salt in the passwords file
      new_login = {user: {'hash': hashed, 'salt': salt}}

      try:
        with open(PASSWORDS_PATH, 'r') as file:
          pwds = json.load(file)
          pwds.update(new_login)
      except FileNotFoundError:
        pwds = new_login

      with open(PASSWORDS_PATH, 'w') as file:
        json.dump(pwds, file)

      print(f"{prefix} Login added successfully")
      continue

    if cmd == "SHUTDOWN":
      print(f"{prefix} Shutting down")
      shutdown = True
      break

    print(f"{prefix} Command not recognized")


def main():
  print("Starting the server")

  if not os.path.exists(PROJECT_DATA_DIR):
    print("Project data directory")
    os.mkdir(PROJECT_DATA_DIR)

  if not os.path.exists(FILE_STORAGE_DIR):
    print("Created storage directory")
    os.mkdir(FILE_STORAGE_DIR)

  thread = threading.Thread(target=handle_cli)
  thread.start()

  server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # used IPV4 and TCP connection
  server.bind(ADDR) # bind the address
  server.listen() # start listening

  print(f"Server is listening on {IP}:{PORT}")

  try:
    while True:
      conn, addr = server.accept() # accept a connection from a client

      thread = threading.Thread(target=handle_client, args=(conn, addr)) # assigning a thread for each client
      thread.start()
  except:
    print("Server interrupted")

  print("Shutting down server...")
  shutdown = True
  try:
    server.close()
  except:
    pass


if __name__ == "__main__":
  main()