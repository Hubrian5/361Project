from Crypto.PublicKey import RSA

print("Generating keys")
client = 1
while(client < 7):
    key = RSA.generate(2048)
    publicKey = key.publickey()
    if (client < 6):
        file_clientside = open("./client/client" + str(client) + "/client" + str(client) + "_private.pem", "wb")
        file_clientside.write(key.exportKey())
        file_clientside.close()
        file_clientside = open("./client/client" + str(client) + "/client" + str(client) + "_public.pem", "wb")
        file_clientside.write(publicKey.exportKey())
        file_clientside.close()
        file_serverside = open("./server/client" + str(client) + "/client" + str(client) + "_public.pem", "wb")
        file_serverside.write(publicKey.exportKey())
        file_serverside.close()        
    else:
        file_serverside = open("./server/server_private.pem", "wb")
        file_serverside.write(key.exportKey())
        file_serverside.close()
        file_serverside = open("./server/server_public.pem", "wb")
        file_serverside.write(publicKey.exportKey())
        file_serverside.close()
        i = 1
        while(i < 6):
            file_serverside = open("./client/client" + str(i) + "/server_public.pem", "wb")
            file_serverside.write(publicKey.exportKey())
            file_serverside.close()  
            i += 1
    
    client +=1
        
    
print("Keys generated")



