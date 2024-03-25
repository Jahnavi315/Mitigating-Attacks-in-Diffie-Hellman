#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <gmp.h>
#include <openssl/sha.h>

#define MAX_ID_LENGTH 32
#define MAX_PASSWORD_LENGTH 32
#define NODE_PORT 9999
#define NONCE_LENGTH 32
#define HASH_LENGTH 32

char ipaddr[16];
char my_id[MAX_ID_LENGTH + 1];//IDs are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
int port;

// Function to compute SHA-256 hash
void computeSHA256(const unsigned char input[], size_t input_len, unsigned char output[]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(output, &ctx);
}

// Function to print hash value
void printHash(const unsigned char hash[], size_t hash_len) {
	printf("Hash Value : ");
    	for (size_t i = 0; i < hash_len; i++) {
        	printf("%02x", hash[i]);
    	}
    	printf("\n");
}

void extract_nonce(unsigned char xored_nonce[],unsigned char nonce[]){
	int bytes_read,bytes_sent;
	
	printf("Xored-Nonce content: ");
	for (size_t i = 0; i < NONCE_LENGTH; i++) {
		printf("%02X ", xored_nonce[i]);
	}
	printf("\n");
	    	
    	//extracting nonce
    	printf("Enter your password to continue : ");
    	fflush(stdout);
    	
    	char password[MAX_PASSWORD_LENGTH + 1];
    	bytes_read = read(0,password,sizeof password);
    	if(bytes_read == -1){
    		perror("read");
    		return;
    	}
    	password[bytes_read - 1] = '\0';
    	printf("Password content: ");
    	for (size_t i = 0; i < strlen(password); i++) {
		printf("%02X ", (unsigned char)password[i]);
    	}
    	printf("\n");
    	fflush(stdout);
    	
    	int p_index = strlen(password) - 1;
    	
    	for(int i=31;i>=0;i--){
		if(p_index != -1){
			nonce[i] = xored_nonce[i] ^ (unsigned char)(password[p_index--]);
		}else{
			nonce[i] = xored_nonce[i];
		}
	}
	
	//printing nonce extracted
	printf("Nonce content: ");
    	for (size_t i = 0; i < NONCE_LENGTH; i++) {
		printf("%02X ", nonce[i]);
    	}
    	printf("\n");
    	
}

void* node_as_A(void* args){
	int bytes_read,bytes_sent;

	//IDs input
	char req_id[MAX_ID_LENGTH + 1];
	//IDs are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
	char req_ipaddr[16];
	
	printf("Enter Y if you want to start key exchange !\n");
	if(getchar() != 'Y')return NULL;
	getchar();
		
	//Connecting to server
	int sfd = socket(AF_INET,SOCK_STREAM,0);
	
	struct sockaddr_in serveraddr;
	
	memset(&serveraddr,0,sizeof serveraddr);	
	serveraddr.sin_family=AF_INET;
	if (inet_pton(AF_INET, "127.0.0.5", &serveraddr.sin_addr) != 1) {
		perror("inet_pton");
	}
	serveraddr.sin_port=htons(9898);
	
	int st = connect(sfd,(struct sockaddr*)&serveraddr,sizeof serveraddr);
	if(st<0){
		perror("connect ");
	}else{
		printf("Connection established with server\n");
		
		printf("Enter id of other node : ");
		fflush(stdout);
		
		bytes_read = read(0,req_id,MAX_ID_LENGTH + 1);
		if(bytes_read == -1){
			perror("read");
		}else{
			req_id[bytes_read -1] = '\0';
			printf("Requesting id : %s\n",req_id);
		}
	
		//Asking for node-B ipaddr
		printf("Enter Node-B IP address : ");
		fflush(stdout);
		bytes_read = read(0,req_ipaddr,sizeof req_ipaddr);
		req_ipaddr[bytes_read - 1] = '\0';
	
		//send ids
		char ids[2*MAX_ID_LENGTH + 20];
		sprintf(ids,"%s||%s||%s",my_id,req_id,req_ipaddr);
		printf("Sending ids : %s\n",ids);
		bytes_sent = send(sfd,ids,strlen(ids),0);
		if(bytes_sent != strlen(ids)){
			perror("send");
		}else{
			printf("Sent ids to the server\n");
		}
		
		unsigned char nonce[NONCE_LENGTH];		
		unsigned char xored_nonce[NONCE_LENGTH];
		
		printf("Extracting nonce..\n");
		//rcv xored_nonce
		bytes_read = recv(sfd,xored_nonce,sizeof xored_nonce,0);
		if(bytes_read != NONCE_LENGTH){
			//when xored_nonce is not of 32 bytes!!
			printf("Did not receive 32 bytes!\n");
			return NULL;
		}
		extract_nonce(xored_nonce,nonce);
	}
}

void* node_as_B(void* args){

	int bytes_read,bytes_sent;

	int sfd = socket(AF_INET,SOCK_STREAM,0);
	
	int option=1;
	setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR|SO_REUSEPORT,&option,sizeof option);
	
	struct sockaddr_in addr;
	memset(&addr,0,sizeof addr);
	
	addr.sin_family=AF_INET;
	
	if (inet_pton(AF_INET, ipaddr, &addr.sin_addr) != 1) {
		perror("inet_pton");
	}
	addr.sin_port=htons(NODE_PORT);
	
	if(bind(sfd,(struct sockaddr*)&addr,sizeof addr)==-1){
		perror("bind ");
	}
	
	listen(sfd,3);
	
	//accept req from server
	int nsfd = accept(sfd,NULL,NULL);
	if(nsfd != -1){
		printf("Server established connection!\n");
		
		unsigned char buff[NONCE_LENGTH + 2 + HASH_LENGTH];
		unsigned char xored_nonce[NONCE_LENGTH];
		unsigned char nonce[NONCE_LENGTH];
		unsigned char hashed_value_ob[HASH_LENGTH];
		
		printf("Extracting nonce..\n");
		//rcv xored_nonce
		bytes_read = recv(nsfd,buff,sizeof buff,0);
		if(bytes_read == -1){
			perror("recv");
			return NULL;
		}
		
		for(int i=0;i<NONCE_LENGTH;i++){
			xored_nonce[i] = buff[i];
		}
		extract_nonce(xored_nonce,nonce);
		
		for(int i=0;i<HASH_LENGTH;i++){
			hashed_value_ob[i] = buff[NONCE_LENGTH + 2 + i];
		}
		
		printf("Obtained ");
		printHash(hashed_value_ob,sizeof hashed_value_ob);
	}
}


int main(){

	int bytes_read,bytes_sent;

	printf("Enter your id : ");
	fflush(stdout);
	
	bytes_read = read(0,my_id,MAX_ID_LENGTH + 1);
	if(bytes_read == -1){
		perror("read");
	}else{
		my_id[bytes_read -1] = '\0';
		printf("Your id : %s\n",my_id);
	}
	
	printf("Enter Your IP address : ");
	fflush(stdout);
	bytes_read = read(0,ipaddr,sizeof ipaddr);
	ipaddr[bytes_read - 1] = '\0';
		
	
	pthread_t A,B;
	pthread_create(&A,NULL,node_as_A,NULL);
	pthread_create(&B,NULL,node_as_B,NULL);
	while(1){}
}
