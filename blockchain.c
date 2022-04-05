#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "blockchain.h"
#include <openssl/sha.h>


void save_block(Block *b){
    FILE *f=fopen("block.txt","w");
    CellProtected *cp=b->votes;
    char *kstr=key_to_str(b->author);
    char *pstr=NULL;

    fprintf(f,"%s %s %s %d\n",kstr,b->hash,b->previous_hash,b->nonce);
    free(kstr);

    while (cp!=NULL){
        pstr=protected_to_str(cp->data);
        fprintf(f,"%s\n",pstr);
        free(pstr);
        cp=cp->next;
    }
    fclose(f);
}

Block *read_block(char *filename){
    FILE *f=fopen(filename,"r");
    Block *b=(Block *)malloc(sizeof(Block));
    char kstr[256];
    char pstr[512];
    b->votes=NULL;
    char buffer[512];
    fgets(buffer,512,f);
    sscanf(buffer,"%s %s %s %d",kstr,b->hash,b->previous_hash,&(b->nonce));
    b->author=str_to_key(kstr);

    while (fgets(buffer,512,f)!=NULL){
        sscanf(buffer,"%s",pstr);
        b->votes=add_head_cellprotected(b->votes,str_to_protected(pstr));
    }
    fclose(f);
    return b;
}

char *block_to_str(Block *block){
    char *res=(char *)malloc(sizeof(char)*2056);
    char cpstr[1024];
    char cpstrtmp[256];
    CellProtected *tmp=block->votes;
    while (tmp!=NULL){
        sprintf(cpstrtmp,"%s %s %s\n",key_to_str(tmp->data->pKey),tmp->data->mess,signature_to_str(tmp->data->sgn));
        strcat(cpstr,cpstrtmp);
        tmp=tmp->next;
    }
    sprintf(res,"%s %s \n%s %d",key_to_str(block->author),block->previous_hash,cpstr,block->nonce);
    return res;
}

unsigned char *func_sha(const char *str){
    return SHA256(str,strlen(str),0);
}

int compute_proof_of_work(Block *b,int d){
    unsigned char *hash;
    const char nonce[256];
    for(int i=0;i<2147483647;i++){
        b->nonce=i;
        itoa(b->nonce,nonce,10);
        hash=sha256(nonce,strlen(nonce),0);
    }
}