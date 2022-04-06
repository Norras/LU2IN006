
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include "blockchain.h"
#include <math.h>
#include "protocol.h"
#include "prime.h"
#include "secure.h"
#include <time.h>
#include <stdlib.h>




int main(){
    const char *s="Rosetta code";
    unsigned char *d=SHA256((const unsigned char*)s,strlen(s),0);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",d[i]);
    }
    putchar('\n');
    char test=d[0];
    printf("%x\n",test);
    Block *b=(Block *)malloc(sizeof(Block));
    generate_random_data(50,20);
    b->author=(Key *)malloc(sizeof(Key));
    init_key(b->author,558,133);
    b->votes=read_protected();
    b->previous_hash=NULL;
    b->hash=(unsigned char *)malloc(sizeof(unsigned char)*512);
    compute_proof_of_work(b,2);

}

