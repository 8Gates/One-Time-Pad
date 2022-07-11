#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]){
    /* Creates a key file of specified length printing to stdout. Pseudo random
    characters are selected from A-Z and ' '. File length is specified length
    +1 as '\n' is printed following key generation. */
    
    // validate the correct number of arguments were passed
    if(argc != 2){
        fprintf(stderr, "Usage: %s key_length\n", argv[0]); 
		exit(0);
    }
    
    // seed with random time
    srand(time(0));  
    
    char charList[27] = { ' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z'};
    
    // Using modular arithmetic print key of specified length 
    for(int i =0;i<atoi(argv[1]);i++)
		printf("%c", charList[rand()%27]);
		
    printf('\n');
    return 0;
}