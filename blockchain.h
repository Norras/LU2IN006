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


void save_block(Block *b,char *filename);
Block *read_block(char *filename);
unsigned char *func_sha(const char *str);
char *block_to_str(Block *block);
void compute_proof_of_work(Block *b,int d);
int verify_block(Block *b,int d);
void delete_block(Block *b);
void create_block(CellTree **tree,Key *author,int d);
void add_block(int d,char *name);
void submit_vote(Protected *p);

CellTree *create_node(Block *b);
int update_height(CellTree *father,CellTree *child);
void add_child(CellTree *father,CellTree *child);
void print_tree(CellTree *racine,int prof);
void delete_node(CellTree *node);
void delete_tree(CellTree *tree);
CellTree *highest_child(CellTree *cell);
CellTree *last_node(CellTree *tree);
CellProtected *fusion_highest_CP(CellTree *racine);
CellTree *read_tree();
Key *compute_winner_BT(CellTree *tree,CellKey *candidates,CellKey *voters,int sizeC,int sizeV);


#endif