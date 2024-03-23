#include <stdio.h>
#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>
#include<arpa/inet.h>
#include<string.h>

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
	addr.sin_addr.s_addr=htonl(INADDR_ANY);
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

void generate_send_nonce(int nsfd){

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
    	
    	int sz = send(nsfd,nonce,count,0);
    	if(sz != count){
    		perror("send ");
    	}
    	
}

int main() {
	
	create_socket();
	
	initiate_generator();
	
    	int nsfd = accept(sfd,NULL,NULL);
	if(nsfd == -1){
		perror("accept ");
	}else{
		printf("accepted client\n");
		generate_send_nonce(nsfd);
	}
    	    	
    	mpz_clear(random_number);
    	gmp_randclear(state);
    	
    	while(1){}
}
