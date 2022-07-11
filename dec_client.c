// One-Time Pad dec_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <sys/stat.h>
#include <netdb.h>      
#include <fcntl.h>


/* 
* Send a verification message to the server.If a terminate message is received in
* reply then set exit status to 2. Decryption server should only stay connected to 
* decryption client.
*/
void validateServer(int socketFD, int port) {
    char buffer[100];
    int writeCount = 0;
    int charsWritten = 0;
    int charsRead = 0;
    memset(buffer, '\0', sizeof(buffer));
    strcpy(buffer, "dec_client");
    char* pointer = buffer;

    // server replies 'terminate' if the first message received is not 'dec_client'
    // Send message to server, loop to make sures all complete message is sent
    while (writeCount < 10) {
        charsWritten = write(socketFD, pointer, 10); // write buffer pointer to socket
        if (charsWritten < 0) {
            fprintf(stderr, "CLIENT: Error send() on authorization for port %d", port);
            exit(2); // if dec_client cannot connect to dec_server set exit value to 2
        }
        // increment the buffer pointer and total number of characters written 
        writeCount += charsWritten;
        pointer += charsWritten; 
    }
    memset(buffer, '\0', sizeof(buffer));
    // Read the server's response from the socket, exit if there is a read error
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
    if (charsRead < 0) {
        fprintf(stderr, "CLIENT: Unauthorized access to port %d", port);
        close(socketFD);
        exit(2); // if dec_client cannot connect to dec_server set exit value to 2
    } 
    // Server sent a terminate message, the port number for enc_server was used 
    if (strcmp(buffer, "terminate") == 0) {
        fprintf(stderr, "CLIENT: Unauthorized access to port %d", port);
        close(socketFD);
        exit(2); // if dec_client cannot connect to dec_server set exit value to 2
    }
}

/* 
* Verify message contains valid charactersand return message length 
*/
int verifyMessage(char* fileName) {
    FILE* fp;
    char smallbuff[1000];
    char *buffer = malloc(100000 * sizeof(char));
    memset(buffer, '\0', sizeof(buffer));

    // open file for reading, if file pointer is not returned, NULL is returned on error 
    fp = fopen(fileName, "r");
    if (fp == NULL) {
        free(buffer);
        fprintf(stderr,"Error opening file to verify characters");
        return(-1);
    }
    
    // read 100 characters at a time into smallbuff, append smallbuff to buffer and 
    // continue until the file is read 
    while (fgets(smallbuff, sizeof(smallbuff), fp) != NULL) {
        smallbuff[strcspn(smallbuff, "\n")] = '\0';
        strcat(buffer, smallbuff);
        memset(smallbuff, '\0', sizeof(smallbuff));
    }
    fclose(fp); // close the file 

    // validate characters in argument fileName are valid for encryption,
    // all generated keys should end with \n , skip character check of last index
    for (int i = 0; i < strlen(buffer)-1; i++) {
        // Valid ASCII numbers are A-Z : 65-90 and ' ' : 32
        if ((int)buffer[i] < 65 && (int)buffer[i] != 32) {
            free(buffer);
            fprintf(stderr, "CLIENT: Error invalid characters in %s index %d\n", fileName, i);
            exit(1); // bad characters set exit value to 1 
        }
        if ((int)buffer[i] > 90) {
            free(buffer);
            fprintf(stderr, "CLIENT: Error invalid characters in %s index %d\n", fileName, i);
            exit(1); // bad characters set exit value to 1
        }
    }
    // return the length of the file
    free(buffer);
    return strlen(buffer);
}


/*
* Open and read the message from the file 'fileName' into the buffer. Write the buffer
* to the decryption server.
*/
void writeToServer(char* fileName, int fileLength, int socketFD) {  
    int readCount, readEnd, writeCount, charsWritten;
    writeCount = 0;
    charsWritten = 0;
    char* pointer;
    char smallbuff[1000];
    char* buffer = malloc(100000 * sizeof(char));
    memset(buffer, '\0', sizeof(buffer));
    FILE* fp;

    // open file for reading, if file pointer is not returned, NULL is returned on error 
    fp = fopen(fileName, "r"); 
    if (fp == NULL) {
        free(buffer);
        fprintf(stderr, "CLIENT: Error opening file %s", fileName);
        exit(1);
    }

    // read 100 characters at a time into smallbuff, append smallbuff to buffer and 
    // continue until the file is read 
    while (fgets(smallbuff, sizeof(smallbuff), fp) != NULL) {
        smallbuff[strcspn(smallbuff, "\n")] = '\0';
        strcat(buffer, smallbuff);
        memset(smallbuff, '\0', sizeof(smallbuff));
    } 
    fclose(fp); // close file 

    // Send the message to the server in chunks, loop until the number of characters written
    // to the server equals the number of characters read from the file. Use pointer to track 
    // and write from the correct location
    readCount = strlen(buffer);
    pointer = buffer;
    while (writeCount < readCount) {
        charsWritten = write(socketFD, pointer, readCount); // write pointer buffer to socket
        if (charsWritten < 0) {
            free(buffer);
            fprintf(stderr, "Client: Error writing %s to socket\n", fileName);
            exit(1);
        }
        // increment the buffer pointer and total number of characters written 
        writeCount += charsWritten; 
        pointer += charsWritten; 
    }
    free(buffer);
    return;
}

/* 
* Set up the address struct 
*/
void setupAddressStruct(struct sockaddr_in* address,
    int portNumber,
    char* hostname) {

    // Clear out the address struct
    memset((char*)address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);

    // Get the DNS entry for this host name
    struct hostent* hostInfo = gethostbyname(hostname);
    if (hostInfo == NULL) {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(0);
    }
    // Copy the first IP address from the DNS entry to sin_addr.s_addr
    memcpy((char*)&address->sin_addr.s_addr,
        hostInfo->h_addr_list[0],
        hostInfo->h_length);
}

/*
* dec_client is passed a message filename, key filename and port number for the dec_server.
* main verifies the key is sufficient length, the message contains no invalid characters,
* and then sends both to the decryption server. The decrypted message is printed to stdout
* once received from the server.
*/
int main(int argc, char* argv[]) {
    int socketFD, charsRead;
    struct sockaddr_in serverAddress;
    char* buffer = malloc(100000 * sizeof(char));
    // Check usage & args
    if (argc != 4) {
        free(buffer);
        fprintf(stderr, "USAGE: %s message key port\n", argv[0]);
        exit(2);
    }
    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        free(buffer);
        fprintf(stderr, "CLIENT: ERROR opening socket");
        exit(2);
    }
    // Allows sockets to bind() to this port, unless there is an active listening socket bound already.
    int optval = 1;
    setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    // Set up the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");
  
    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        free(buffer);
        fprintf(stderr, "CLIENT: ERROR connecting");
        exit(2);
    }
    // validate connection to the correct server : dec_client to dec_server
    validateServer(socketFD, atoi(argv[3]));

    // verify message and key contain correct characters and get their lengths
    int messageLen = verifyMessage(argv[1]);
    int keyLen = verifyMessage(argv[2]);
    if (keyLen < messageLen) {
        free(buffer);
        fprintf(stderr, "CLIENT: Key length too short.");
        exit(1); // key file too short set exit value to 1 
    }
    // send message and key to the decryption server 
    writeToServer(argv[1], messageLen - 1, socketFD);
    writeToServer(argv[2], keyLen - 1, socketFD);

    // Read the server's deciphered response from the socket and write it to the buffer
    charsRead = recv(socketFD, buffer, 100000, 0);
    if (charsRead < 0) {
        fprintf(stderr, "CLIENT: Error reading cipher from socket");
        free(buffer);
        exit(-1);
    }
    // print deciphered text with newline and close socket
    printf("%s\n", buffer);
    free(buffer);
    close(socketFD);
    exit(0);
}
