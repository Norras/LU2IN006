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
#include <dirent.h>
#include "winner.h"

#define D 3

void jefree(CellTree *tree){
    if (tree!=NULL){
    jefree(tree->firstChild);
    jefree(tree->nextBro);
    free(tree->block->author);
    free(tree->block->hash);
    free(tree->block->previous_hash);
    free(tree->block);
    free(tree);
    }
}
int main(){
    generate_random_data(1000,5);
    CellProtected *votes=read_protected("declarations.txt");
    CellKey *keys=read_public_keys("keys.txt");
    CellKey *candidates=read_public_keys("candidates.txt");

    CellProtected *tmp=votes;
    CellTree *tree=NULL;
    int c=1;
    int fc=0;
    char filename[256];
    while (tmp!=NULL){
        submit_vote(tmp->data);
        if (c%10==0){
            sprintf(filename,"Blockchain/Block%d.txt",fc);
            create_block(&tree,tmp->data->pKey,D);
            add_block(D,filename);

            fc++;
        }
        c++;
        tmp=tmp->next;
    }
    CellTree *rtree=read_tree();
    print_tree(rtree,0);

    Key *k=compute_winner_BT(rtree,candidates,keys,5,1000);
    char *kstr=key_to_str(k);
    printf("GRAND GAGNANT : %s\n",kstr);

    free(k);
    free(kstr);

    delete_tree(tree);
    jefree(rtree);
    delete_list_keys(keys);
    delete_list_keys(candidates);
    delete_list_protected(votes);


    
    

    return 0;
}