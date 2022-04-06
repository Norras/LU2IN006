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
char *hextobin(unsigned char hex){  
    char *res=(char *)malloc(sizeof(char)*1024); 
       switch(hex){  
           case '0':  
           return "0000";
           break;
           case '1':
           return "0001";  
           break;  
           case '2':  
           return "0010"; 
           break;  
           case '3':  
           return "0011";  
           break;  
           case '4':
           return "0100";  
           break;  
           case '5':  
           return "0101";
           break;  
           case '6':  
           return "0110";  
           break;  
           case '7':  
           return "0111";
           break;  
           case '8':  
           return "1000";
           break;  
           case '9':  
            return "1001";
           break;   
           case 'a':  
           return "1010";  
           break;   
           case 'b':  
           return "1011";
           break;   
           case 'c':  
           return "1100";  
           break;   
           case 'd':  
           return "1101";
           break;   
           case 'e':  
           return "1110";
           break;   
           case 'f':  
           return "1111";
           break;  
       }    
       return " ";
}


int compute_proof_of_work(Block *b,int d){
    unsigned char *hash;
    char *hashbin;
    char nonce[256];
    int boolean;
    int i;
    for(i=0;i<2147483647;i++){
        b->nonce=i;
        sprintf(nonce,"%d",b->nonce);
        hash=SHA256((const unsigned char *)nonce,strlen(nonce),0);
        

        if (strlen((char *)hash)<d){
            continue;
        }

        boolean=1;
        for(int j=0;j<d;j++){
            char t=hash[j];
            printf("%d\n",t);
            if (t!='0'){
                boolean=0;
                printf("%d - %d -- NON VALIDE\n",i,t);
                affichage(hash,i,"non valide.");
                break;
            }
        }
        if (boolean==1){
            b->hash=hash;
            affichage(hash,i,"valide !");
            return i;
        }
    }
    printf("On a rien trouvé\n");
    return i;
}

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
