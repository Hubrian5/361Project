import socket
import sys
import os
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def server():
    #Server port
    serverPort = 13000
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    print('The server is ready to accept connections')
        
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
        
    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            #print(addr,'   ',connectionSocket)
            pid = os.fork()
            
            # If it is a client process
            if  pid== 0:
                
                serverSocket.close() 
                with open('user_pass.json', 'r') as file:                 
                    # Read file containing actual user from json file
                    realUsersPasswords = json.load(file)
                    realUserName = list(realUsersPasswords.keys())
                #Get server private RSA key
                serverPrivate = open('server_private.pem', 'r')
                serverPrivateKey = RSA.import_key(serverPrivate.read())
                serverPrivate.close()
                rsa_server = PKCS1_OAEP.new(serverPrivateKey)
                #Get user name
                userName = connectionSocket.recv(2048)
                userName = rsa_server.decrypt(userName)
                userName = unpad(userName,16)  
                userName = userName.decode('ascii')
                #Get password        
                password = connectionSocket.recv(2048)
                password = rsa_server.decrypt(password)
                password = unpad(password,16)  
                password = password.decode('ascii')
                if(userName in realUserName): #Check if user name vaild
                    if(realUsersPasswords[userName] == password): #If user name is vaild check password
                        print("Connection Accepted and Symmetric Key Generated for client: " + userName) #Password and user name match
                        currentClientPublic = open("./" + userName + "/" + userName + "_public.pem", 'r') #Get client public key
                        currentClientPublicKey = RSA.import_key(currentClientPublic.read())
                        currentClientPublic.close() 
                        rsa_client = PKCS1_OAEP.new(currentClientPublicKey)
                        sym_key = get_random_bytes(32)  #Generate a random 256 bit symmetric key
                        message = rsa_client.encrypt(pad(sym_key,16)) #Encrypt new key and send to user
                        connectionSocket.send(message)
                        cipher = AES.new(sym_key, AES.MODE_ECB) #Create AES cipher
                    else: #Password did not match
                        message = "Invalid username or password.\nTerminating.".encode('ascii')
                        connectionSocket.send(message)
                        print("The received client information: " + userName + " is invalid (ConnectionTerminated).")
                        break
                else: #Username did not match
                    message = "Invalid username or password.\nTerminating".encode('ascii')
                    print("The received client information: " + userName + " is invalid (ConnectionTerminated).")
                    connectionSocket.send(message)
                    break
                
                confirm = connectionSocket.recv(2048)
                confirm = cipher.decrypt(confirm)
                confirm = unpad(confirm, 16)
                confirm = confirm.decode('ascii')
                if(confirm == "OK"):
                    userChoice = '0'
                    while(userChoice != '4'):
                        menu = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n"
                        menu = cipher.encrypt(pad(menu.encode('ascii'),16))
                        connectionSocket.send(menu)
                        userChoice = connectionSocket.recv(2048)
                        userChoice = cipher.decrypt(userChoice)
                        userChoice = unpad(userChoice, 16)
                        userChoice = userChoice.decode('ascii')
                #Parent doesn't need this connection
                connectionSocket.close()
                return
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        except:
            serverSocket.close() 
            sys.exit(0)
            
        
#-------
server()
