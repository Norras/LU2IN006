
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
    srand(time(NULL));
    const char *s="Rosetta code";
    unsigned char *d=SHA256((const unsigned char*)s,strlen(s),0);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",d[i]);
    }
    putchar('\n');
    char test=d[0];
    printf("%x\n",test);
    Block *b=(Block *)malloc(sizeof(Block));
    generate_random_data(10,5);
    b->author=(Key *)malloc(sizeof(Key));
    init_key(b->author,558,133);
    b->votes=valid_list_protected(read_protected());
    b->previous_hash=NULL;
    b->nonce=0;
    char *strb=block_to_str(b);
    unsigned char *hashed=func_sha(strb);
    free(strb);
    printf("HASH : %s\n",hashed);
    free(hashed);
    b->hash=strdup("hash");
    
    b->nonce=550;
    // printf("Liste protected: %s\n",CPlist_to_str(b->votes));
    free(b->hash);
    clock_t begin=time(NULL);
    compute_proof_of_work(b,6);
    clock_t end=time(NULL);
    printf( "Finished in %.4ld sec\n",(unsigned long)difftime(end,begin));  

    CellProtected *l1=valid_list_protected(read_protected());
    // generate_random_data(15,2);
    CellProtected *l2=valid_list_protected(read_protected());
    fusion_cell_protected(l1,l2);
    //print_list_protected(l1);
    
    delete_list_protected(l1);
    free(b->author);
    delete_block(b);
}

