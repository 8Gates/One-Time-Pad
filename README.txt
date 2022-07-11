****************** Run Test Script ******************

1) Run the following command in the same directory as the provided files
	$ compileall

2) Run the provided test script 
	$ p5testscript 58149 58148 > mytestresults 2>&1


****************** Run Manually ******************
 
1) start servers in the background with unused port numbers
	$ enc_server 57282 &
	$ dec_server 57283 &

2) generate a key with the length at least as long as your message
	$ keygen 100 > keyFile

3) enrcypt plain text file 
	$ ./enc_client messageFile keyFile 57282 > testEnc

4) decrypt encrypted file 
	$ ./dec_client testEnc keyFile 57283 > testDec