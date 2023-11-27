'''
server.py
Author(s): 
Course: CMPT361-X01L
Instructor: Mohammed Elmorsy
Project
Date: November 24, 2023
'''
import socket
import sys
import os
import json
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def server():
    #Server port
    serverPort = 17000
    
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
                        message, cipher = create_cipher(userName)
                        #print(cipher, message) dev check
                        connectionSocket.send(message) 
                    else: #Password did not match
                        message = "Invalid username or password.\nTerminating.".encode('ascii')
                        connectionSocket.send(message)
                        print("The received client information: " + userName + " is invalid (ConnectionTerminated).")
                        break
                else: #Username did not match
                    message = "Invalid username or password.\nTerminating.".encode('ascii')
                    print("The received client information: " + userName + " is invalid (ConnectionTerminated).")
                    connectionSocket.send(message)
                    break
                
                confrim = connectionSocket.recv(2048)
                confrim = cipher.decrypt(confrim)
                confrim = unpad(confrim, 16)
                confrim = confrim.decode('ascii')
                if(confrim == "OK"):
                    userChoice = '0'
                    while userChoice != '4':
                        menu = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n"
                        menu = cipher.encrypt(pad(menu.encode('ascii'),16))
                        connectionSocket.send(menu)
                        userChoice = connectionSocket.recv(2048)
                        userChoice = decrypt_bytes(userChoice, cipher)
                        if userChoice == '1':
                            print("protocol 1")
                            emailMessage = "Enter destinations (separated by ;): "
                            emailMessage = encrypt_message(emailMessage, cipher)
                            connectionSocket.send(emailMessage)
                            email = connectionSocket.recv(2048)
                            email = decrypt_bytes(email, cipher)
                            
                            titleMessage = "Enter title: "
                            titleMessage = encrypt_message(titleMessage, cipher)
                            connectionSocket.send(titleMessage)
                            title = connectionSocket.recv(2048)
                            title = decrypt_bytes(title, cipher)
                            
                            
                            loadQuery = "Would you like to load contents from a file? (Y/N) "
                            loadQuery = encrypt_message(loadQuery, cipher)
                            connectionSocket.send(loadQuery)
                            answer = connectionSocket.recv(2048)
                            answer = decrypt_bytes(answer, cipher)
                            if(answer == 'Y'):
                                #User wants to load contents from a file
                                ContentMessage = "Enter filename: "
                                ContentMessage = encrypt_message(ContentMessage, cipher)
                                connectionSocket.send(ContentMessage)
                            elif(answer == 'N'):
                                #User wants to type a message
                                ContentMessage = "Enter message contents: "
                                ContentMessage = encrypt_message(ContentMessage, cipher)
                                connectionSocket.send(ContentMessage)
                            
                            messageContents = connectionSocket.recv(2048)
                            messageContents = decrypt_bytes(messageContents, cipher)
                            #Get date and time
                            currentTime = str(datetime.datetime.now())
                            print(email)
                            print(title)
                            print(currentTime)
                            print(answer)
                            print(messageContents)
                            
                            #Now server will save the email data to a file
                            rClients = email.split(';')
                            for client in rClients:
                                path = "./" + client + "/" + userName + "_" + title + ".txt"
                                newEmail = open(path, 'w')
                                newEmail.write("From: " + userName + "\n")
                                newEmail.write("To: " + email + "\n")
                                newEmail.write("Time and Date: " + currentTime + "\n")
                                newEmail.write("Content Length: " + str(len(messageContents)) + "\n")
                                newEmail.write("Content:\n")
                                newEmail.write(messageContents)
                                newEmail.close
                                
                            
                        if userChoice == '2':
                            print("protocol 2")
                            message = "Hi"
                            message = encrypt_message(message, cipher) 
                            connectionSocket.send(message)
                            ok = connectionSocket.recv(2048) #confirmation
                            ok = decrypt_bytes(ok, cipher)
                            print(ok) #dev check
                            
                        if userChoice == '3':
                            print("protocol 3")
                            index = "Enter the email you wish to view: "
                            index = encrypt_message(index, cipher)
                            connectionSocket.send(index)
                            index = connectionSocket.recv(2048)
                            index = decrypt_bytes(index, cipher)
                            print(index) #dev check
                            
                            message = "Hi"
                            message = encrypt_message(message, cipher) 
                            connectionSocket.send(message)
                            
                            ok = connectionSocket.recv(2048) #confirmation
                            ok = decrypt_bytes(ok, cipher)
                            print(ok) #dev check
                            
                        if userChoice == '4':
                            message = "Terminate"
                            message = encrypt_message(message, cipher)
                            connectionSocket.send(message)
                            break
                #Parent doesn't need this connection
                print("Terminating connection with {user}.".format(user = userName))
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
'''
Function gets the key from the key file, gets and sym key and returns cipher
'''
def create_cipher(userName):
    fName = "./" + userName + "/" + userName + "_public.pem" #Get client public key
    with open(fName, 'r') as currentClientPublic:
        currentClientPublicKey = RSA.import_key(currentClientPublic.read())
        rsa_client = PKCS1_OAEP.new(currentClientPublicKey)
        sym_key = get_random_bytes(32)  #Generate a random 256 bit symmetric key
        message = rsa_client.encrypt(pad(sym_key,16)) #Encrypt new key and send to user
        cipher = AES.new(sym_key, AES.MODE_ECB) #Create AES cipher
    return message, cipher
    
'''
Function takes a string message,encodes and encrypts it (AES) using the key with ECB mode. Function
returns the encrypted message.
'''
def encrypt_message(message, cipher):
    m_bytes = cipher.encrypt(pad(message.encode('ascii'),16))
    return m_bytes

'''
Function takes an encrypted message in AES mode ECB format, and the key to decrypt the message. 
Function returns the decrypted message
'''
def decrypt_bytes(m_bytes, cipher):
    
    #Start of decryption
    Padded_message = cipher.decrypt(m_bytes)
    
    #Remove padding
    Encodedmessage = unpad(Padded_message,16)
    Encodedmessage = Encodedmessage.decode('ascii')
    return Encodedmessage
server()
