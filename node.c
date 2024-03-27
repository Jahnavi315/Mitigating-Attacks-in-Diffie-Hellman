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
#define NODE_B_PORT 9999
#define NONCE_LENGTH 32
#define HASH_LENGTH 32
#define MAX_PU_KEY_LENGTH 32

char ipaddr[16];
char my_id[MAX_ID_LENGTH + 1];//IDs are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
int port;

void print(unsigned char buff[],int len){
	for(int i=0;i<len;i++){
		printf("%02X ",buff[i]);
	}
	printf("\n");
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

int checkIfHashMatch(unsigned char h1[],unsigned char h2[]){
	for(int i=0;i<HASH_LENGTH;i++){
		if(h1[i] != h2[i]){
			return 0;
		}
	}
	return 1;
}



void extract_nonce(unsigned char nonce_xor_password[],unsigned char nonce[]){
	int bytes_read,bytes_sent;
	
	printf("Nonce XOR Password : ");
	print(nonce_xor_password,NONCE_LENGTH);
	    	
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
    	printf("Your Password is : ");
    	print((unsigned char*)password,strlen(password));
    	
    	int p_index = strlen(password) - 1;
    	
    	for(int i=31;i>=0;i--){
		if(p_index != -1){
			nonce[i] = nonce_xor_password[i] ^ (unsigned char)(password[p_index--]);
		}else{
			nonce[i] = nonce_xor_password[i];
		}
	}
	
	//printing nonce extracted
	printf("Nonce : ");
    	print(nonce,NONCE_LENGTH);
    	
}

void* node_as_A(void* args){

	printf("Executing as Node - A\n");
	
	int bytes_read,bytes_sent;

	//IDs input
	char id_b[MAX_ID_LENGTH + 1];
	//IDs are in char type and also store \0 at the end , these will be converted into unsigned char type when required in the code
	char ipaddr_b[16];
		
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
		
		printf("Enter ID of Node - B : ");
		fflush(stdout);
		
		bytes_read = read(0,id_b,MAX_ID_LENGTH + 1);
		if(bytes_read == -1){
			perror("read");
		}else{
			id_b[bytes_read -1] = '\0';
			printf("Node-B ID %s ...\n",id_b);
		}
	
		//Asking for node-B ipaddr
		printf("Enter Node-B IP address : ");
		fflush(stdout);
		bytes_read = read(0,ipaddr_b,sizeof ipaddr_b);
		ipaddr_b[bytes_read - 1] = '\0';
	
		//send ids
		char ids__ip[2*MAX_ID_LENGTH + 20];
		sprintf(ids__ip,"%s||%s||%s",my_id,id_b,ipaddr_b);
		printf("Sending IDs,IP : %s\n",ids__ip);
		bytes_sent = send(sfd,ids__ip,strlen(ids__ip),0);
		if(bytes_sent != strlen(ids__ip)){
			perror("send");
		}else{
			printf("Sent IDs to the server\n");
		}
		
		unsigned char nonce[NONCE_LENGTH];		
		unsigned char nonce_xor_password[NONCE_LENGTH];
		
		printf("Extracting nonce..\n");
		//rcv nonce_xor_password
		bytes_read = recv(sfd,nonce_xor_password,sizeof nonce_xor_password,0);
		if(bytes_read != NONCE_LENGTH){
			//when nonce_xor_password is not of 32 bytes!!
			printf("Did not receive 32 bytes!\n");
			return NULL;
		}
		extract_nonce(nonce_xor_password,nonce);
		
		//Start Key exchange process
		
		unsigned char Ya[MAX_PU_KEY_LENGTH];
		unsigned char Ya__nonce[MAX_PU_KEY_LENGTH + 2 + NONCE_LENGTH];
		unsigned char hash_Ya__nonce[HASH_LENGTH];
		//buffer to be sent to node B
		unsigned char Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + MAX_ID_LENGTH];
		
		//computing YA to be done later
		
		
		
		for(int i=0;i<MAX_PU_KEY_LENGTH;i++){
			Ya__nonce[i] = Ya[i];
			Ya__hash_Ya__nonce__ida[i] = Ya[i];
		}
		
		Ya__nonce[MAX_PU_KEY_LENGTH] = Ya__nonce[MAX_PU_KEY_LENGTH + 1] = '|';
		Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH] = Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 1] = '|';
		
		for(int i=0;i<NONCE_LENGTH;i++){
			Ya__nonce[MAX_PU_KEY_LENGTH + 2 + i] = nonce[i];
		}
		
		//printing Ya__nonce content
		printf("YA||Nonce : ");
		print(Ya__nonce,sizeof Ya__nonce);
		
		computeSHA256(Ya__nonce,sizeof Ya__nonce,hash_Ya__nonce);
		printf("YA||Nonce ");
		printHash(hash_Ya__nonce);
		
		for(int i=0;i<HASH_LENGTH;i++){
			Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + i] = hash_Ya__nonce[i];
		}
		
		Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH] = Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 1] = '|';
		
		for(int i=0;i<strlen(my_id);i++){
			Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2 + i] = (unsigned char)my_id[i];
		}
		
		//print the buffer we are sending - Ya__hash_Ya__nonce__ida
		printf("YA||(H(YA||nonce)||IDA) : ");
		print(Ya__hash_Ya__nonce__ida,sizeof Ya__hash_Ya__nonce__ida);
		
		//Connect to Node - B
		int bsfd = socket(AF_INET,SOCK_STREAM,0);
	    	
	    	struct sockaddr_in b_addr;
	
		memset(&b_addr,0,sizeof b_addr);	
		b_addr.sin_family=AF_INET;
		if (inet_pton(AF_INET, ipaddr_b, &b_addr.sin_addr) != 1) {
			perror("inet_pton");
		}
		b_addr.sin_port=htons(NODE_B_PORT);
		
		int st = connect(bsfd,(struct sockaddr*)&b_addr,sizeof b_addr);
		if(st<0){
			perror("connect ");
		}else{
			perror("connect ");
			printf("Connection with Node-B successful\n");
			bytes_sent = send(bsfd,Ya__hash_Ya__nonce__ida,sizeof Ya__hash_Ya__nonce__ida,0);
			if(bytes_sent != sizeof Ya__hash_Ya__nonce__ida){
				perror("send ");
			}
		}
		
	}
}

void* node_as_B(void* args){
	
	printf("Executing as Node - B\n");

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
	addr.sin_port=htons(NODE_B_PORT);
	
	if(bind(sfd,(struct sockaddr*)&addr,sizeof addr)==-1){
		perror("bind ");
	}
	
	listen(sfd,3);
	
	//accept req from server
	int nsfd = accept(sfd,NULL,NULL);
	if(nsfd != -1){
		printf("Server established connection!\n");
		
		unsigned char nonce_xor_p__hash_nonce_xor_p__ida[NONCE_LENGTH + 2 + HASH_LENGTH];
		unsigned char nonce_xor_password[NONCE_LENGTH];
		unsigned char nonce[NONCE_LENGTH];
		unsigned char rcvd_hash_nonce_xor_p__ida[HASH_LENGTH];
		
		printf("Extracting nonce..\n");
		//rcv nonce_xor_password
		bytes_read = recv(nsfd,nonce_xor_p__hash_nonce_xor_p__ida,sizeof nonce_xor_p__hash_nonce_xor_p__ida,0);
		if(bytes_read == -1){
			perror("recv");
			return NULL;
		}
		
		for(int i=0;i<NONCE_LENGTH;i++){
			nonce_xor_password[i] = nonce_xor_p__hash_nonce_xor_p__ida[i];
		}
		extract_nonce(nonce_xor_password,nonce);
		
		for(int i=0;i<HASH_LENGTH;i++){
			rcvd_hash_nonce_xor_p__ida[i] = nonce_xor_p__hash_nonce_xor_p__ida[NONCE_LENGTH + 2 + i];
		}
		
		printf("Rcvd(from Server) (Nonce XOR password)||IDA ");
		printHash(rcvd_hash_nonce_xor_p__ida);
		
		//accept connection request from Node - A
		int nsfd_a = accept(sfd,NULL,NULL);
		if(nsfd_a != -1){
			printf("Accepted Node - A's connection request!\n");
			
			unsigned char rcvd_Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + MAX_ID_LENGTH];
			unsigned char rcvd_Ya[MAX_PU_KEY_LENGTH];
			unsigned char rcvd_hash_Ya__nonce[HASH_LENGTH];
			unsigned char rcvd_ida[MAX_ID_LENGTH];
			unsigned char comp_Ya__nonce[MAX_PU_KEY_LENGTH + 2 + NONCE_LENGTH];
			unsigned char comp_hash_Ya__nonce[HASH_LENGTH];
			
			bytes_read = recv(nsfd_a,rcvd_Ya__hash_Ya__nonce__ida,sizeof rcvd_Ya__hash_Ya__nonce__ida,0);
			if(bytes_read == -1){
				perror("recv ");
				return NULL;
			}
			
			printf("Rcvd YA||(H(YA||nonce))||IDA : ");
			print(rcvd_Ya__hash_Ya__nonce__ida,sizeof rcvd_Ya__hash_Ya__nonce__ida);
			
			//Extract YA
			for(int i=0;i<MAX_PU_KEY_LENGTH;i++){
				rcvd_Ya[i] = rcvd_Ya__hash_Ya__nonce__ida[i];
				comp_Ya__nonce[i] = rcvd_Ya__hash_Ya__nonce__ida[i];
			}
			
			printf("Rcvd YA : ");
			print(rcvd_Ya,sizeof rcvd_Ya);
			
			//Extract H(YA||nonce)
			for(int i=0;i<HASH_LENGTH;i++){
				rcvd_hash_Ya__nonce[i] = rcvd_Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + i];
			}
			
			//printing hash of YA||nonce
			printf("Rcvd YA||Nonce ");
			printHash(rcvd_hash_Ya__nonce);
			
			//Extract IDA
			for(int i=0;i<MAX_ID_LENGTH;i++){
				rcvd_ida[i] = rcvd_Ya__hash_Ya__nonce__ida[MAX_PU_KEY_LENGTH + 2 + HASH_LENGTH + 2 + i];
			}
			
			printf("Rcvd IDA from A : ");
			print(rcvd_ida,sizeof rcvd_ida);
			
			//Find YA||Nonce
			comp_Ya__nonce[MAX_PU_KEY_LENGTH] = comp_Ya__nonce[MAX_PU_KEY_LENGTH + 1] = '|';
			
			for(int i=0;i<NONCE_LENGTH;i++){
				comp_Ya__nonce[MAX_PU_KEY_LENGTH + 2 + i] = nonce[i];//this nonce was sent by AS 
			} 
			
			computeSHA256(comp_Ya__nonce,sizeof comp_Ya__nonce,comp_hash_Ya__nonce);
			
			printf("Computed YA||Nonce ");
			printHash(comp_hash_Ya__nonce);
			
			//check if rcvd hash(from A) and computed hash of : YA(rcvd from A) || nonce(rcvd from server) match!
			int hash_Ya__nonce_matched = checkIfHashMatch(comp_hash_Ya__nonce,rcvd_hash_Ya__nonce);
			
			if(!hash_Ya__nonce_matched){
				printf("HASH MISMATCH!!\nTerminated\n");
				return NULL;
			}
			printf("Received and Computed Hash of YA||Nonce MATCHED..\n");
			
			//check if Nonce XOR Password (rcvd from server) || ida (rcvd from A) hash value match with the H(Nonce XOR Password || IDA) (sent by)
			unsigned char comp_nonce_xor_p__ida[NONCE_LENGTH + 2 + MAX_ID_LENGTH];
			unsigned char comp_hash_nonce_xor_p__ida[HASH_LENGTH];
			
			for(int i=0;i<NONCE_LENGTH;i++){
				comp_nonce_xor_p__ida[i] = nonce_xor_password[i];
			}
			
			comp_nonce_xor_p__ida[NONCE_LENGTH] = comp_nonce_xor_p__ida[NONCE_LENGTH + 1] = '|';
			
			for(int i=0;i<MAX_ID_LENGTH;i++){
				comp_nonce_xor_p__ida[NONCE_LENGTH + 2 + i] = rcvd_ida[i];
			}
			
			computeSHA256(comp_nonce_xor_p__ida,sizeof comp_nonce_xor_p__ida,comp_hash_nonce_xor_p__ida);
			printf("Computed Nonce XOR Password || IDA ");
			printHash(comp_hash_nonce_xor_p__ida);
			
			int hash_nonce_xor_p__ida_matched = checkIfHashMatch(comp_hash_nonce_xor_p__ida,rcvd_hash_nonce_xor_p__ida);
			
			if(!hash_nonce_xor_p__ida_matched){
				printf("HASH MISMATCH!!\nTERMINATED\n");
			}
			printf("Hashes of Nonce XOR Password || IDA MATCHED..\n");
			
		}
	}
}


int main(){

	int bytes_read,bytes_sent;

	printf("Enter your ID : ");
	fflush(stdout);
	
	bytes_read = read(0,my_id,MAX_ID_LENGTH + 1);
	if(bytes_read == -1){
		perror("read");
	}else{
		my_id[bytes_read -1] = '\0';
		printf("Your ID is : %s\n",my_id);
	}
	
	printf("Enter Your IP address : ");
	fflush(stdout);
	bytes_read = read(0,ipaddr,sizeof ipaddr);
	ipaddr[bytes_read - 1] = '\0';
		
	printf("Enter Y if you want to start key exchange !\n");
	pthread_t A,B;
	char c = getchar();
	getchar();
	if(c != 'Y'){
		pthread_create(&B,NULL,node_as_B,NULL);
	}else{
		pthread_create(&A,NULL,node_as_A,NULL);
	}
		
	while(1){}
}
