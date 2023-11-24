import socket
import sys
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
            
    
def client():
    # Server Information
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
        
        #Get server response for validating user info
        reply = clientSocket.recv(2048)
        if(reply == "Invalid username or password.\nTerminating.".encode('ascii')): #Check if server vaildated user
            print(reply.decode('ascii')) #User was not vaildated
            clientSocket.close()
        else: #User was validated
            currentClientPrivate = open(userName + "_private.pem", 'r') #Get client public key
            currentClientPrivateKey = RSA.import_key(currentClientPrivate.read())
            currentClientPrivate.close() 
            rsa_client = PKCS1_OAEP.new(currentClientPrivateKey)
            #Get and create symmetric key
            sym_key = rsa_client.decrypt(reply)
            sym_key = unpad(sym_key,16)  
            cipher = AES.new(sym_key, AES.MODE_ECB) #Create AES cipher
        #Send confirm message to server stating that we have recived the symmetric key
        confirm = cipher.encrypt(pad("OK".encode('ascii'),16))
        clientSocket.send(confirm)
        userChoice = '0'
        while(userChoice != '4'):
            menu = clientSocket.recv(2048)
            menu = cipher.decrypt(menu)
            menu = unpad(menu,16)
            menu = menu.decode('ascii')
            print(menu)
            userChoice = input("\tChoice: ")
            sendUserChoice = cipher.encrypt(pad(userChoice.encode('ascii'),16))
            clientSocket.send(sendUserChoice)
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
