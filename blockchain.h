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

typedef struct block_tree_cell{
    Block *block;
    struct block_tree_cell *father;
    struct block_tree_cell *firstChild;
    struct block_tree_cell *nextBro;
    int height;
}CellTree;
void save_block(Block *b);
Block *read_block(char *filename);
unsigned char *func_sha(const char *str);
char *block_to_str(Block *block);
int compute_proof_of_work(Block *b,int d);
int compute_proof_of_work2(Block *b,int d);
int verify_block(Block *b,int d);
int perfs(Block *b,int d);
void delete_block(Block *b);

CellTree *create_node(Block *b);
int update_height(CellTree *father,CellTree *child);
void add_child(CellTree *father,CellTree *child);
void print_tree(CellTree *racine);
#endif