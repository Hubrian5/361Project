'''
server.py
Author(s): Brian Hu, Haris Kajtazovic, Mitch Duriez
Course: CMPT361-X01L
Instructor: Mohammed Elmorsy
Project
Date: November 24, 2023
'''
import socket
import sys
import os
import glob
import json
import datetime
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
                if(userName in realUserName): #Check if user name valid
                    if(realUsersPasswords[userName] == password): #If user name is valid check password
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
                
                # Receive OK from client
                confirm = connectionSocket.recv(2048)
                confirm = cipher.decrypt(confirm)
                confirm = unpad(confirm, 16)
                confirm = confirm.decode('ascii')
                if(confirm == "OK"):
                    userChoice = '0'
                    while userChoice != '4':
                        menu = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n"
                        menu = cipher.encrypt(pad(menu.encode('ascii'),16))
                        connectionSocket.send(menu)
                        userChoice = connectionSocket.recv(2048)
                        userChoice = decrypt_bytes(userChoice, cipher)
                        if userChoice == '1':
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
                            answer = answer.upper()
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
                            fileSize = connectionSocket.recv(2048)
                            fileSize = decrypt_bytes(fileSize,cipher)
                            bytes_read = 0
                            messageContents = ""
                            while(bytes_read < int(fileSize)): #get full content length
                                bytesRecv = connectionSocket.recv(2048)
                                bytesRecv = decrypt_bytes(bytesRecv, cipher)
                                messageContents += bytesRecv #Store converted message bytes into readable text
                                bytes_read += len(bytesRecv.encode('ascii'))
                            #Get date and time
                            currentTime = str(datetime.datetime.now())
                            
                            #Now server will save the email data to a file
                            rClients = email.split(';')
                            for client in rClients:
                                pathTitle = title.replace(" ", "_")
                                if(client in realUserName):
                                    path = "./" + client + "/" + userName + "_" + pathTitle + ".txt"
                                    newEmail = open(path, 'w')
                                    newEmail.write("From: " + userName + "\n")
                                    newEmail.write("To: " + email + "\n")
                                    newEmail.write("Time and Date: " + currentTime + "\n")
                                    newEmail.write("Title: " + title + "\n")
                                    newEmail.write("Content Length: " + str(len(messageContents)) + "\n")
                                    newEmail.write("Content:\n")
                                    newEmail.write(messageContents)
                                    newEmail.close()
                            print("An email from " + userName + " is sent to " + email + " has a content length of " + str(len(messageContents)) + " .")
                                    
                                
                            
                        if userChoice == '2':
                            emails_info = []

                            try:
                                emails_info = get_files(userName)
                                print(emails_info)
                                for i in range(0,len(emails_info)):
                                    emails_info[i][0] = i+1
                                #print("AFTERMATH\n" + emails_info)
                                # Determine maximum lengths of columns
                                max_lengths = [len(col) for col in ["Index", "From", "DateTime", "Title"]]
                                for info in emails_info:
                                    for i, length in enumerate(max_lengths):
                                        max_lengths[i] = max(max_lengths[i], len(str(info[i])))
                                
                                # Prepare the inbox information message with left-aligned columns
                                column_names = ["Index", "From", "DateTime", "Title"]
                                column_template = ' '.join([f'{{:<{length}}}' for length in max_lengths])
                                inbox_message = column_template.format(*column_names) + '\n'
                                
                                if not emails_info:
                                    empty_inbox_message = "Inbox is empty"
                                    encrypted_empty_inbox_message = encrypt_message(empty_inbox_message, cipher)
                                    connectionSocket.send(encrypted_empty_inbox_message)
                                else:
                                    for info in emails_info:
                                        inbox_message += column_template.format(*map(str, info)) + '\n'
                                    #print(inbox_message)
                                    
                                    # Encrypt and send the inbox information message to the client
                                    encrypted_inbox_message = encrypt_message(inbox_message, cipher)
                                    connectionSocket.send(encrypted_inbox_message)
                                #print(encrypted_inbox_message)
                                #print("Inbox information sent.")
                                
                            except FileNotFoundError:
                                print(f"No inbox information found for {userName}")

                            # Waiting for confirmation from the client
                            ok = connectionSocket.recv(2048) #confirmation
                            ok = decrypt_bytes(ok, cipher)
                            #print(ok) #dev check
                            
                        if userChoice == '3':
                            #get index from user
                            index = "Enter the email you wish to view: "
                            index = encrypt_message(index, cipher)
                            connectionSocket.send(index)
                            index = connectionSocket.recv(2048)
                            index = decrypt_bytes(index, cipher)
                            index = int(index) - 1 
                            #print(index) #dev check
                            
                            emails_info = get_files(userName)
                            
                            if len(emails_info) != 0 and index < len(emails_info): #Error check
                                email = emails_info[index]
                                email_message, size = read_file(email[1], email[3], userName)
                                fileSize = encrypt_message(size, cipher)
                                connectionSocket.send(fileSize)
                                
                                # Waiting for confirmation from the client
                                ok = connectionSocket.recv(2048) #confirmation
                                ok = decrypt_bytes(ok, cipher)
                                #print(ok) #dev check
                                
                                email_message = cipher.encrypt(pad(email_message, 16))
                                connectionSocket.sendall(email_message)
                                
                            else:
                                message = "Inbox empty or file not found"
                                message = encrypt_message(message, cipher)
                                connectionSocket.send(message)
                                
                            # Waiting for confirmation from the client
                            ok = connectionSocket.recv(2048) #confirmation
                            ok = decrypt_bytes(ok, cipher)
                            #print(ok) #dev check
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
    
    if(len(Padded_message) != 2048):
        #Remove padding
        Encodedmessage = unpad(Padded_message,16)
        Encodedmessage = Encodedmessage.decode('ascii')
    else:
        Encodedmessage = Padded_message.decode('ascii')
    
    return Encodedmessage
'''
Function globs all files from client folders, goes over the files and creates a list of the inbox.
Function sorts and returns the list
'''
def get_files(userName):
    # Retrieve all the files in the respective clients folder
    email_files = glob.glob(f"./{userName}/*.txt")
    #print(email_files)                           
    
    # Extract email information
    emails_info = []
    for index, file_path in enumerate(email_files, start=1):
        with open(file_path, 'r') as email_content:
            lines = email_content.readlines()
            if len(lines) >= 4:
                from_client = lines[0][6:].strip()  # Extract 'From: clientX'
                date_time = lines[2][15:].strip()  # Extract 'Time and Date: YYYY-MM-DD HH:MM:SS...'
                title = lines[3][7:].strip()[:100]  # Extract 'Title: ...' with max length of 100
                emails_info.append([index, from_client, date_time, title])
    #print(emails_info)
                                
    # Sort emails_info by date and time (assuming the third element is the date and time string)
    emails_info.sort(key=lambda x: x[2])
    return emails_info

'''

'''
def read_file(sender, title, userName):
    pathTitle = title.replace(" ", "_")
    fPath = ("./{user}/" + sender + "_" + pathTitle + ".txt").format(user = userName)
    #print(fPath) #Dev check
    fileSize = str(os.stat(fPath).st_size)
    content = b""
    with open(fPath, "rb") as f:
        content +=  f.read(int(fileSize))
    return content, fileSize
server()
