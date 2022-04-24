
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

int main(){
    srand(time(NULL));
    // Essai SHA256
    const char *s="Rosetta code";
    unsigned char *d=SHA256((const unsigned char*)s,strlen(s),0);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",d[i]);
    }
    putchar('\n');
    Block *b=(Block *)malloc(sizeof(Block));
    generate_random_data(10,1);
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
    compute_proof_of_work(b,3);
    clock_t end=clock();
    printf( "Finished in %.3f sec\n",(double)(end -  begin)/ CLOCKS_PER_SEC);
    printf("Verify Block : %d\n",verify_block(b,3));
    CellProtected *l1=valid_list_protected(read_protected("declarations.txt"));
    // generate_random_data(15,2);
    CellProtected *l2=valid_list_protected(read_protected("declarations.txt"));
    fusion_cell_protected(&l1,l2);
    //print_list_protected(l1);


    CellTree *tree=NULL;

    Key *key=(Key *)malloc(sizeof(Key));
    init_key(key,551,220);
    CellProtected *cp=valid_list_protected(read_protected("declarations.txt"));
    CellProtected *headcp=cp;
    while (cp!=NULL){
        submit_vote(cp->data);
        cp=cp->next;
    }

    create_block(&tree,key,3);
    printf("%s\n",block_to_str(tree->block));
    add_block(3,"Blockchain/block21.txt");
    srand(time(NULL)*rand());
    generate_random_data(10,1);
    cp=valid_list_protected(read_protected("declarations.txt"));
    while (cp!=NULL){
        submit_vote(cp->data);
        cp=cp->next;
    }
    create_block(&tree,key,3);
    printf("-----\n");
    print_tree(tree,0);
    printf("-----\n");
    add_block(3,"Blockchain/block12.txt");
    delete_list_protected(headcp);
    free(key);
    free(b->author);
    delete_tree(tree);
    delete_list_protected(l1);


    DIR *rep=opendir("./Blockchain/");
    if (rep !=NULL){
        struct dirent *dir;
        while ((dir=readdir(rep))){
            if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
                printf("Chemin du fichier : ./Blockchain/%s \n",dir->d_name);
            }
        }
        closedir(rep);
    }
    print_tree(read_tree(),0);
}



// int main(){
//     int z=5;
//     double temps=0;
//     FILE *f=fopen("data.txt","a");
//     for(int i=0;i<20;i++){
//         generate_random_data(20,5);
//         Block *b=(Block *)malloc(sizeof(Block));
//         Key *k=(Key *)malloc(sizeof(Key));
//         CellProtected *d=valid_list_protected(read_protected("declarations.txt"));
//         init_key(k,551,58);
//         b->votes=d;
//         b->previous_hash=NULL;
//         b->author=k;
//         clock_t begin=clock();
//         compute_proof_of_work(b,z);
//         clock_t end=clock();
//         temps+=(double)(end -  begin)/ CLOCKS_PER_SEC;
//     }
//     fclose(f);
//     fprintf(f,"%d %f\n",z,temps/20);
//     return 0;
// };