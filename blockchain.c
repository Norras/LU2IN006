#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "blockchain.h"
#include <openssl/sha.h>
#include "secure.h"


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
    return SHA256((const unsigned char *)str,strlen(str),0);
}
void affichage(unsigned char *hash,int j,char *message){
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",hash[i]);
    }
    printf(" %d ---- %s\n",j,message);
}


int compute_proof_of_work(Block *b,int d){
    unsigned char *hash;
    char nonce[256];
    char zeros[d+1];
    memset(zeros,'0',d);
    zeros[d]='\0';
    for(int i=0;i<2147483647;i++){
        sprintf(nonce,"%d",i);
        hash=SHA256(nonce,strlen(nonce),0);
        hash[d]='\0';
        if (strcmp(hash,zeros)==0){
            printf("%d -- VALIDE\n",i);
            b->nonce=i;
            return i;
        }
    }
    b->nonce=-1;
    printf("On a rien trouvé\n");
    return -1;
}

// int compute_proof_of_work2(Block *b,int d){
//     unsigned char *hash;
//     char nonce[256];
//     sprintf(nonce,"0");
//     hash=SHA256(nonce,strlen(nonce),0);
//     char zeros[d+1];
//     memset(zeros,'0',d);
//     zeros[d]='\0';
//     int i=0;
//     while(strcmp((char *)hash,zeros)!=0){
//         sprintf(nonce,"%d",i);
//         hash=SHA256(nonce,strlen(nonce),0);
//         i++;
//     }
//     b->nonce=i;
//     return i;
// }
int verify_block(Block *b,int d){
    char nonce[256];
    sprintf(nonce,"%d",b->nonce);
    unsigned char *hash=SHA256((const unsigned char *)nonce,strlen(nonce),0);
    if (strlen((char *)hash)< d){
        return 0;
    }
    for(int i=0;i<d;i++){
        if (hash[i]!='0'){
            return 0;
        }
    }
    return 1;
}
