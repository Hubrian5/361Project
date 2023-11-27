'''
client.py
Author(s): 
Course: CMPT361-X01L
Instructor: Mohammed Elmorsy
Project
Date: November 24, 2023
'''
import socket
import sys
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
            
    
def client():
    # Server Information
    serverName = input("Enter the server IP or name: ")
    serverPort = 17000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        #Get server public RSA key
        serverPublic = open('server_public.pem', 'r')
        serverPublicKey = RSA.import_key(serverPublic.read())
        serverPublic.close()
        rsa_server = PKCS1_OAEP.new(serverPublicKey)
        
        userName = input("Enter your username: ")
        message = userName.encode('ascii')
        message = rsa_server.encrypt(pad(message,16)) #encrypt user input and send to server
        clientSocket.send(message)
        password = input("Enter your password: ")
        message = password.encode('ascii')
        message = rsa_server.encrypt(pad(message,16)) #encrypt user input and send to server
        clientSocket.send(message)
        
        #Get server response for vaildating user info
        reply = clientSocket.recv(2048)
        if(reply == "Invalid username or password.\nTerminating.".encode('ascii')): #Check if server vaildated user
            print(reply.decode('ascii')) #User was not vaildated
            clientSocket.close()
            return
        else: #User was vaildated
            cipher = create_cipher(userName, reply)
            
        #Send confrim message to server stating that we have recived the symmetric key
        confrim = cipher.encrypt(pad("OK".encode('ascii'),16))
        clientSocket.send(confrim)
        choice = '0'
        while choice != '4':
            menu = clientSocket.recv(2048)
            menu = cipher.decrypt(menu)
            menu = unpad(menu,16)
            menu = menu.decode('ascii')
            print(menu)
            userChoice = input("\tChoice: ")
            choice = userChoice #choice taken from user input
            sendUserChoice = cipher.encrypt(pad(userChoice.encode('ascii'),16))
            clientSocket.send(sendUserChoice)
            message = clientSocket.recv(2048)
            message = decrypt_bytes(message, cipher)
            if choice == '1':
                print("Entering Sp1") #dev check
                #Enter client destinations
                destination = input(message)
                destination = encrypt_message(destination, cipher)
                clientSocket.send(destination)
                #Title of the email
                message = clientSocket.recv(2048)
                message = decrypt_bytes(message, cipher)
                while(True):
                    title = input(message)
                    if(len(title) > 100):
                        print("Title length is too long, title must be less than 100 characters")
                    else:
                        break
                title = encrypt_message(title, cipher)
                clientSocket.send(title)
                #Pick if user wants to load from a file or not
                message = clientSocket.recv(2048)
                message = decrypt_bytes(message, cipher)
                query = input(message)
                query = query.upper()
                sQuery = encrypt_message(query, cipher)
                clientSocket.send(sQuery)
                if(query == 'Y'):
                    #User wants to load contents from a file
                    message = clientSocket.recv(2048)
                    message = decrypt_bytes(message, cipher)
                    while(True):
                        fileName = input(message)
                        fileOpen = open(fileName, "r")
                        fileContents = fileOpen.read()
                        if(len(fileContents) > 1000000):
                            print("Message contents too long, message contents must be less than 1000000 characters")
                        else:
                            break
                    sendContents = encrypt_message(fileContents, cipher)
                    clientSocket.send(sendContents)
                    
                elif(query == 'N'):
                    #User wants to type a message
                    message = clientSocket.recv(2048)
                    message = decrypt_bytes(message, cipher)
                    while(True):
                        emailMessage = input(message)
                        if(len(emailMessage) > 1000000):
                            print("Message contents too long, message contents must be less than 1000000 characters")
                        else:
                            break 
                    sendContents = encrypt_message(emailMessage, cipher)
                    clientSocket.send(sendContents)
                #client is finished sending email data
                
            if choice == '2':
                print("Entering Sp2") #dev check
                print(message)
                ok = "OK"
                ok = encrypt_message(ok, cipher)
                clientSocket.send(ok)
                
            if choice == '3':
                print("Entering Sp3") #dev check
                index = input(message)
                index = encrypt_message(index, cipher)
                clientSocket.send(index)
                
                email = clientSocket.recv(2048)
                email = decrypt_bytes(email, cipher)
                print(email)
                
                ok = "OK"
                ok = encrypt_message(ok, cipher)
                clientSocket.send(ok)
               
        # Client terminate connection with the server
        print("The connection is terminated with the server.")
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
'''
Function gets the key from the key file, gets and sym key and returns cipher
'''
def create_cipher(user_Name, reply):
    fName = user_Name + "_private.pem"
    with open(fName, "r") as currentClientPrivate:
        currentClientPrivateKey = RSA.import_key(currentClientPrivate.read())
    rsa_client = PKCS1_OAEP.new(currentClientPrivateKey)
    #Get and create symmetric key
    sym_key = rsa_client.decrypt(reply)
    sym_key = unpad(sym_key,16)  
    cipher = AES.new(sym_key, AES.MODE_ECB) #Create AES cipher
    return cipher
    
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
    
client()