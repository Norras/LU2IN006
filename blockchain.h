#ifndef __H_BLOCKCHAIN__
#define __H_BLOCKCHAIN__
#include "list_data.h"
#include "secure.h"

typedef struct block{
    Key *author;
    CellProtected *votes;
    unsigned char *hash;
    unsigned char *previous_hash;
    int nonce;
}Block;

void save_block(Block *b);
Block *read_block(char *filename);
unsigned char *func_sha(const char *str);
char *block_to_str(Block *block);
int compute_proof_of_work(Block *b,int d);
int verify_block(Block *b,int d);

#endif