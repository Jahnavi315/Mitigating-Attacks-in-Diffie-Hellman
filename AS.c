#include <stdio.h>
#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>

#define MAX_ID_LENGTH 32
#define MAX_PASSWORD_LENGTH 32
#define MAX_LINE_LENGTH 200
#define NODE_B_PORT 9999
#define HASH_LENGTH 32
#define NONCE_LENGTH 32

mpz_t random_number;
gmp_randstate_t state;//store the state and algo
int sfd;

void print(unsigned char buff[],int len){
	for(int i=0;i<len;i++){
		printf("%02X ",buff[i]);
	}
	printf("\n");
}

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

// Function to compute SHA-256 hash
void computeSHA256(const unsigned char input[], size_t input_len, unsigned char output[]) {

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(output, &ctx);
}

// Function to print hash value
void printHash(const unsigned char hash[]) {

	printf("hash Value : ");
    	for (size_t i = 0; i < HASH_LENGTH; i++) {
        	printf("%02x", hash[i]);
    	}
    	printf("\n");
}

void* serve_clients(void* args){

	int bytes_read,bytes_sent;
		
	printf("server thread initiated\n\n");
	int nsfd = *(int*)args;
	
	//rcv ids
	char ids[2*MAX_ID_LENGTH + 20];
	char ipaddr[16];
	
	bytes_read = recv(nsfd,ids,sizeof ids,0);
	if(bytes_read == -1){
		perror("rcv");
	}else{
		ids[bytes_read] = '\0';
		printf("rcvd ids %s\n\n",ids);
	}
	
	//seperate ids
	
	char* token;
	//IDs are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
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
        	id2[MAX_ID_LENGTH] = '\0'; 
    	}else{
    		printf("Error: Unable to extract id2\n");
    	}
    	
    	// Get the next token (ipaddr of B)
    	token = strtok(NULL, "||");

    	// Extract ipaddr
    	if (token != NULL) {
        	strncpy(ipaddr, token, 16);
        	ipaddr[15] = '\0'; 
    	}else{
    		printf("Error: Unable to extract ipaddr of node-B\n");
    	}

    	//printf("id1: %s\n", id1);
    	//printf("id2: %s\n", id2);
    	//printf("ipaddr : %s\n",ipaddr);
	
	//generating nonce
	mpz_urandomb(random_number, state, 256);
    	//gmp_printf("Nonce : %ZX\n", random_number);
    	
    	size_t size = mpz_sizeinbase(random_number, 2);
    	int extra_bits = size % 8;
    	size = size/8;
    	if(extra_bits){
    		size++;
    	}
	//printf("Size reqd : %ld\n",size);
	if(size < NONCE_LENGTH){
		printf("TOO SMALL NONCE GENERATED\n");
	}
    	unsigned char nonce[NONCE_LENGTH];

	size_t count;
    	mpz_export(nonce, &count, 1, sizeof(unsigned char), 1, 0, random_number);
	
	//printf("Count : %ld\n",count);
    	printf("Nonce : ");
    	print(nonce,NONCE_LENGTH);
    	
    	//sending nonce
    	//passwords are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
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
		//printing passwords
	/*	printf("Password for ID %s: %s\n", id1, password1);
		printf("Password-A : ");
	    	print((unsigned char*)password1,strlen(password1));
	    	
		printf("Password for ID %s: %s\n", id2, password2);
		printf("Password-B : ");
	    	print((unsigned char*)password2,strlen(password2));
	*/
		printf("\nFetched passwords successfully!\n\n");
		
		//XOR passwords with nonce
		
		unsigned char nonce_xor_password1[NONCE_LENGTH];
		unsigned char nonce_xor_password2[NONCE_LENGTH];
		int p1_index = strlen(password1) - 1;
		int p2_index = strlen(password2) - 1;
		
		for(int i=NONCE_LENGTH - 1;i>=0;i--){
			if(p1_index != -1){
				nonce_xor_password1[i] = nonce[i] ^ (unsigned char)(password1[p1_index--]);
			}else{
				nonce_xor_password1[i] = nonce[i];
			}
		}
		
		//printing xored nonce
		printf("Nonce XOR PA : ");
	    	print(nonce_xor_password1,NONCE_LENGTH);
	    	
		for(int i=31;i>=0;i--){
			if(p2_index != -1){
				nonce_xor_password2[i] = nonce[i] ^ (unsigned char)(password2[p2_index--]);
			}else{
				nonce_xor_password2[i] = nonce[i];
			}
		}
		printf("Sending Nonce XOR PA to Node-A\n\n");
			    	
	    	//sending nonce XOR password1 to node-1(A)
	    	bytes_sent = send(nsfd,nonce_xor_password1,count,0);
	    	if(bytes_sent != count){
	    		perror("send ");
	    	}
	    	
	    	//sending nonce XOR password2 and hash to node-2(B)
	    	
	    	//send connect request to node - B
	    	int bsfd = socket(AF_INET,SOCK_STREAM,0);
	    	
	    	struct sockaddr_in b_addr;
	
		memset(&b_addr,0,sizeof b_addr);	
		b_addr.sin_family=AF_INET;
		if (inet_pton(AF_INET, ipaddr, &b_addr.sin_addr) != 1) {
			perror("inet_pton");
		}
		b_addr.sin_port=htons(NODE_B_PORT);
		
		int st = connect(bsfd,(struct sockaddr*)&b_addr,sizeof b_addr);
		if(st<0){
			perror("connect ");
		}else{
			printf("Connection to node - B successful\n\n");
			
			unsigned char nonce_xor_p2__id[NONCE_LENGTH + 2 + MAX_ID_LENGTH];
			unsigned char hash_nonce_xor_p2__id[HASH_LENGTH];
			unsigned char nonce_xor_p2__hash_nonce_xor_p2__id[NONCE_LENGTH + 2 + HASH_LENGTH];
			
			for(int i=0;i<NONCE_LENGTH;i++){
				nonce_xor_p2__id[i] = nonce_xor_p2__hash_nonce_xor_p2__id[i] = nonce_xor_password2[i];
			}
			
			nonce_xor_p2__id[NONCE_LENGTH] = nonce_xor_p2__id[NONCE_LENGTH + 1] = '|';
			nonce_xor_p2__hash_nonce_xor_p2__id[NONCE_LENGTH] = nonce_xor_p2__hash_nonce_xor_p2__id[NONCE_LENGTH + 1] = '|';
			
			for(int i=0;i<strlen(id1);i++){
				nonce_xor_p2__id[NONCE_LENGTH + 2 + i] = (unsigned char)id1[i];
			}
			
			//printing xored nonce
			printf("Nonce XOR PB : ");
			print(nonce_xor_password2,NONCE_LENGTH);
			
			printf("(Nonce XOR PB)||IDA : ");
		    	print(nonce_xor_p2__id,sizeof nonce_xor_p2__id);
		    	
		    	
		    	computeSHA256(nonce_xor_p2__id,sizeof nonce_xor_p2__id,hash_nonce_xor_p2__id);
		    	//printf("(Nonce XOR PB)||IDA ");
		    	//printHash(hash_nonce_xor_p2__id);
		    	
		    	printf("Sending (nonce XOR PB) and H((nonce XOR PB)||IDA) to NOde-B..\n");
			
			for(int i=0;i<HASH_LENGTH;i++){
				nonce_xor_p2__hash_nonce_xor_p2__id[NONCE_LENGTH + 2 + i] = hash_nonce_xor_p2__id[i];
			}
			
			bytes_sent = send(bsfd,nonce_xor_p2__hash_nonce_xor_p2__id,sizeof nonce_xor_p2__hash_nonce_xor_p2__id,0);
		    	if(bytes_sent != sizeof nonce_xor_p2__hash_nonce_xor_p2__id){
		    		perror("send ");
		    	}
		}
	    	
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
