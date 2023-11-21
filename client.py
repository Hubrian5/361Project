import socket
import sys
import json
# Checks if the user input username and password match the json file
def authenticate(username, password):
    with open('user_pass.json', 'r') as file:
        user_pass_data = json.load(file)
        if username in user_pass_data and user_pass_data[username] == password:
            return True
        else:
            return False
        
# Function to check safe username input. Stops user from inputting nothing and crashing the program
def get_valid_username():
    while True:
        username = input("Enter your username: ").strip()
        if len(username) < 1:
            print("Username must be at least 1 characters long.")
        elif not username.isalnum():
            print("Username must contain only alphanumeric characters.")
        else:
            return username
            
# Checks for valid password        
def get_valid_password():
    while True:
        password = input("Enter your password: ").strip()
        if len(password) < 1:
            print("Password must be at least 1 characters long.")
        else:
            return password
        
    
def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverName = input("Enter the server IP or name: ")
    serverPort = 13000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        # Logic Start
        #userName = input("Enter your username: ")
        username = get_valid_username()
        #password = input("Enter your password: ")
        password = get_valid_password()
        
        # Authenticate user
        if authenticate(username, password):
            print("Authentication successful!")
        else:
            print("Invalid username or password.\nTerminating.")
            
        
        # Logic End
        
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
