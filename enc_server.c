// One-Time Pad enc_server

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netdb.h>     
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>



/*
* Accepts the encrypted text, filelength and socket. Writes the encrypted
* text back to the client.
*/
void writeCipher(char* cipher, int fileLength, int socketFD) {
    int writeCount, writeEnd, point;
    writeEnd = fileLength; 
    writeCount = 0;
    point = 0;

    // write to the socket until writeEnd (which equals the length of the file)
    // is decremented to zero which signifies the full file is sent
    while (writeEnd > 0) {
        // ssize_t write(int fd, const void *buf, size_t count);
        writeCount = write(socketFD, cipher+point, fileLength);
        writeEnd -= writeCount; // decrement writeEnd by writeCount
        point += writeCount; // increment the point to cipher by the writeCount
        // write() returns -1 if an error is encountered
        if (writeCount == -1) {
            fprintf(stderr, "SERVER: Error writing ciphered text to client socket\n");
            exit(1);
        }
    }
    return;
}

/* Error function used for reporting issues */
void error(const char* msg) {
    perror(msg);
    exit(1);
}

/* Set up the address struct for the server socket */
void setupAddressStruct(struct sockaddr_in* address,
    int portNumber) {

    // Clear out the address struct
    memset((char*)address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);
    // Allow a client at any address to connect to this server
    address->sin_addr.s_addr = INADDR_ANY;
}

/*
* Encrption server is passed a port number. It creates and binds a listening socket for
* connection requests. A connection request forks a child process which retrieves the client
* text and key, encrypts the message and returns the encrypted text via a new socket. The parent
* sets a WNOHANG flag and loops to continue listening which allows concurrent encryption processes.
*/
int main(int argc, char* argv[]) {
    int connectionSocket, charsRead;
    char buffer[100000];
    char key[100000];
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);

    // variables below are for cipher portion of function
    char cipherText[100000];
    char* e, * p;
    int messageNum, keyNum;
    char characters[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

    // Check usage & args
    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    // Create the socket that will listen for connections
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        error("ERROR opening socket");
    }

    // Set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));

    // Associate the socket to the port
    if (bind(listenSocket,
        (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        error("ERROR on binding");
        exit(1);
    }

    // Start listening for connetions. Allow up to 5 connections to queue up
    listen(listenSocket, 5);

    // Accept a connection, blocking if one is not available until one connects
    while (1) {
        // Accept the connection request which creates a connection socket
        connectionSocket = accept(listenSocket,
            (struct sockaddr*)&clientAddress,
            &sizeOfClientInfo);
        if (connectionSocket < 0) {
            error("ERROR on accept");
        }
        int childStatus;
        pid_t spawnPID = fork();
        switch (spawnPID) {
        case -1:
            perror("fork()\n");
            exit(1);
            break;
        case 0:
            // child process starts here to receive and encrypt message and return cipher 
            memset(buffer, '\0', sizeof(buffer));
            // Read the client's message from the socket
            charsRead = recv(connectionSocket, buffer, 255, 0);
            if (charsRead < 0) {
                error("ERROR reading from socket");
            }
            // write a terminate message back to the client, the enc_client message was not
            // received and this server should not stay connected to dec_client
            else if (strcmp(buffer, "enc_client") != 0) {
                charsRead = send(connectionSocket, "terminate", 9, 0);
                if (charsRead < 0) {
                    error("ERROR writing to socket");
                }
                close(connectionSocket); // close socket for this client 
                break;
            }

            // Send a Success message back to the client
            charsRead = send(connectionSocket, "I am the server, and I got your message", 39, 0);
            if (charsRead < 0) {
                error("ERROR writing to socket");
            }

            // Read the client's message and key from the socket 
            memset(buffer, '\0', sizeof(buffer));
            charsRead = recv(connectionSocket, buffer, 100000, 0); // buffer holds plain text messsage
            if (charsRead < 0) {
                error("SERVER: Error reading message from socket");
            }
            charsRead = recv(connectionSocket, key, 100000, 0); // key holds encryption key
            if (charsRead < 0) {
                error("SERVER: Error reading message from socket");
            }

            // This encryption section below and the buffer/key above have all been verified  
            if (strlen(key) < strlen(buffer)) {
                fprintf(stderr, "Key length too short.");
                exit(1);
            }

            /* One-time pad encryption. Accepts a message and key comprised of ASCII numbers
            65-90 and 32. Returns a string of cipher text. */
            for (int i = 0; i < strlen(buffer); i++) { // -1 don't include newline for encryption
                // get the index position of the message element in characters array
                e = strchr(characters, buffer[i]);
                messageNum = (int)(e - characters);
                // get the index position of the key element in characters array
                p = strchr(characters, key[i]);
                keyNum = (int)(p - characters);

                // add the key to the message using modular arithmetic to 
                // encrypt the current element
                if (messageNum + keyNum <= 26) {
                    cipherText[i] = characters[messageNum + keyNum];
                    // printf("msg: %d key: %d cipher %d\n", messageNum, keyNum, messageNum+keyNum);
                }
                else {
                    cipherText[i] = characters[messageNum + keyNum - 27];
                    // printf("msg: %d key: %d cipher %d\n", messageNum, keyNum, messageNum+keyNum-27);
                }
            }
            // printf("MSG: %s\n CIPHER: %s\n", buffer, cipherText);
            // write cipher back to client 
            writeCipher(cipherText, strlen(buffer), connectionSocket);

            // Close the connection socket for this client
            close(connectionSocket);
        default:
            // parent process set WNOHANG flag to not wait on child process 
            spawnPID = waitpid(spawnPID, &childStatus, WNOHANG);
            // printf("PARENT(%d): child(%d) terminated. Exiting\n", getpid(), spawnPID);
        }
    }
    // Stays open for the lifetime of the server
    close(listenSocket);
    return 0;
}
