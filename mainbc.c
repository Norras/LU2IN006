
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
    // Essai SHA256
    const char *s="Rosetta code";
    unsigned char *d=SHA256((const unsigned char*)s,strlen(s),0);
    unsigned char *d1=SHA256((const unsigned char*)s,strlen(s),0);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",d[i]);
    }
    putchar('\n');
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",d1[i]);
    }
    putchar('\n');
    Block *b=(Block *)malloc(sizeof(Block));
    generate_random_data(25,10);
    b->author=(Key *)malloc(sizeof(Key));
    init_key(b->author,558,133);
    b->votes=valid_list_protected(read_protected("declarations.txt"));
    b->previous_hash=NULL;
    b->nonce=0;
    char *strb=block_to_str(b);
    unsigned char *hashed=func_sha(strb);
    free(strb);
    printf("HASH : %s\n",hashed);
    free(hashed);
    b->hash=(unsigned char *)strdup("hash");
    
    b->nonce=550;
    free(b->hash);
    clock_t begin=clock();
    compute_proof_of_work(b,5);
    clock_t end=clock();
    printf( "Finished in %.3f sec\n",(double)(end -  begin)/ CLOCKS_PER_SEC);
    printf("Verify Block : %d\n",verify_block(b,5));
    CellProtected *l1=valid_list_protected(read_protected("declarations.txt"));
    // generate_random_data(15,2);
    CellProtected *l2=valid_list_protected(read_protected("declarations.txt"));
    fusion_cell_protected(l1,l2);
    //print_list_protected(l1);
    
    delete_list_protected(l1);
    free(b->author);
    delete_block(b);


}

