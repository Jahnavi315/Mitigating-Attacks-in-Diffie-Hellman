#include <stdio.h>
#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>

#define MAX_ID_LENGTH 32
#define MAX_PASSWORD_LENGTH 32
#define MAX_LINE_LENGTH 200

mpz_t random_number;
gmp_randstate_t state;//store the state and algo
int sfd;

void create_socket(){

	sfd = socket(AF_INET,SOCK_STREAM,0);
    	
	int option=1;
	setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR|SO_REUSEPORT,&option,sizeof option);
	
	struct sockaddr_in addr;
	memset(&addr,0,sizeof addr);
	
	addr.sin_family=AF_INET;
	if (inet_pton(AF_INET, "127.0.0.5", &addr.sin_addr) != 1) {
		perror("inet_pton");
	}
	addr.sin_port=htons(9898);
	
	if(bind(sfd,(struct sockaddr*)&addr,sizeof addr)==-1){
		perror("bind ");
	}
	
	listen(sfd,3);
}

int initiate_generator(){

	mpz_init(random_number);// initialize to 0
    	gmp_randinit_default(state); //intilaize with default algo - Mersenne Twister algorithm
   
    	int urandom_fd = open("/dev/urandom", O_RDONLY);
    	if (urandom_fd == -1) {
        	perror("Error opening /dev/urandom");
        	return 1;
    	}

    	unsigned char seed_buffer[16];//for randomness in seed
    	int bytes_read = read(urandom_fd, seed_buffer, sizeof(seed_buffer));
    	if (bytes_read != sizeof(seed_buffer)) {
    	    perror("Error reading from /dev/urandom");
    	    return 1;
    	}

    	unsigned long int seed = 0;
    	for (int i = 0; i < sizeof(seed_buffer); ++i) {
    	    seed = (seed << 8) | seed_buffer[i];
    	    //printf("seed %lu , seed_buffer[i]%d %u %c\n",seed,i,seed_buffer[i],seed_buffer[i]);
    	}

    	gmp_randseed_ui(state, seed); //set an initial seed value into state
	
}

void* serve_clients(void* args){

	int bytes_read,bytes_sent;
		
	printf("server thread initiated\n");
	int nsfd = *(int*)args;
	
	//rcv ids
	char ids[2*MAX_ID_LENGTH + 3];
	
	bytes_read = recv(nsfd,ids,sizeof ids,0);
	if(bytes_read == -1){
		perror("rcv");
	}else{
		ids[bytes_read] = '\0';
		printf("rcvd ids %s\n",ids);
	}
	
	//seperate ids
	
	char* token;
	char id1[MAX_ID_LENGTH + 1];
    	char id2[MAX_ID_LENGTH +1];

    	// Tokenize the string based on the delimiter "||"
    	token = strtok(ids, "||");

    	// Extract id1
	if (token != NULL) {
	       	strncpy(id1, token, MAX_ID_LENGTH);
	       	id1[MAX_ID_LENGTH] = '\0'; 
	} else {
	       	printf("Error: Unable to extract id1\n");
    	}

    	// Get the next token (id2)
    	token = strtok(NULL, "||");

    	// Extract id2
    	if (token != NULL) {
        	strncpy(id2, token, MAX_ID_LENGTH);
        	id2[MAX_ID_LENGTH] = '\0'; // Ensure null termination
    	}else{
    		printf("Error: Unable to extract id2\n");
    	}

    	printf("id1: %s\n", id1);
    	printf("id2: %s\n", id2);
	
	//generating nonce
	mpz_urandomb(random_number, state, 256);
    	gmp_printf("Nonce : %ZX\n", random_number);
    	
    	size_t size = mpz_sizeinbase(random_number, 2);
    	int extra_bits = size % 8;
    	size = size/8;
    	if(extra_bits){
    		size++;
    	}
	printf("Size reqd : %ld\n",size);
    	unsigned char nonce[size];

	size_t count;
    	mpz_export(nonce, &count, 1, sizeof(unsigned char), 1, 0, random_number);
	
	printf("Count : %ld\n",count);
    	printf("Nonce content: ");
    	for (size_t i = 0; i < size; i++) {
        	printf("%02X ", nonce[i]);
    	}
    	printf("\n");
    	
    	//sending nonce
    	char password1[MAX_PASSWORD_LENGTH + 1];
    	char password2[MAX_PASSWORD_LENGTH + 1];
    	// Open the file
	FILE* file = fopen("securedb.txt", "r");
		if (file == NULL) {
		perror("Error opening file");
	}

    	
    	// Search for the IDs in the file
    	int found = 0;
    	char temp_id[MAX_ID_LENGTH +1];
    	char temp_password[MAX_PASSWORD_LENGTH + 1];
    	char line[MAX_LINE_LENGTH];
    	
    	while (fgets(line, sizeof(line), file) != NULL) {
    		if(found == 2){
    			break;
    		}
		if (sscanf(line, "%32s %32[^\n]", temp_id, temp_password) == 2) {
	    		if (!strcmp(temp_id,id1)) {
				strcpy(password1,temp_password);
				
				found++;
	    		}else if (!strcmp(temp_id,id2)) {
				strcpy(password2,temp_password);
				found++;
	    		}
		}
    	}
	fclose(file);
	
	// ID not found
	if(found != 2){
		printf("Error in search operation : Id(s) not found\n");
	}else{
		printf("Password for ID %s: %s\n", id1, password1);
		printf("Password for ID %s: %s\n", id2, password2);
		printf("Fetched passwords successfully!\n");
	}
    
    	bytes_sent = send(nsfd,nonce,count,0);
    	if(bytes_sent != count){
    		perror("send ");
    	}
}

int main() {
	
	create_socket();
	
	initiate_generator();
	
	while(1){
	    	int nsfd = accept(sfd,NULL,NULL);
		if(nsfd == -1){
			perror("accept ");
		}else{
			printf("accepted client\n");
			pthread_t server;
			pthread_create(&server,NULL,serve_clients,&nsfd);
		}
    	}
    	mpz_clear(random_number);
    	gmp_randclear(state);
    	
}
