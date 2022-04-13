#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "blockchain.h"
#include <openssl/sha.h>
#include "secure.h"
#include "math.h"


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
    char *res=(char *)malloc(sizeof(char)*256);
    char *cpstrtmp;
    int taille=256;
    CellProtected *tmp=block->votes;
    sprintf(res,"%s %s %s %d\n",key_to_str(block->author),block->previous_hash,block->hash,block->nonce);
    while (tmp!=NULL){
        cpstrtmp=protected_to_str(tmp->data);
        taille+=strlen(cpstrtmp)+1;
        res=(char *)realloc(res,taille);
        strcat(res,cpstrtmp);
        free(cpstrtmp);
        tmp=tmp->next;
    }
    
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
    
    char zeros[d+1];
    memset(zeros,'0',d);
    zeros[d]='\0';
    char *block=CPlist_to_str(b->votes);
    char tohash[strlen(block)+sizeof(int)];
    printf("%s\n",zeros);
    for(int i=0;i<INT32_MAX;i++){
        sprintf(tohash,"%s %d",block,i);
        hash=SHA256((unsigned char *)tohash,strlen(tohash),0);
        hash[d]='\0';
        if (strcmp((const char *)hash,zeros)==0){
            affichage(hash,i,"VALIDE !");
            b->nonce=i;
            return i;
        }
    }
    b->nonce=-1;
    printf("On a rien trouvé\n");
    return -1;
}

int verify_block(Block *b,int d){
    char nonce[256];
    char zeros[d+1];
    
    memset(zeros,'0',d);
    zeros[d]='\0';
    sprintf(nonce,"%d",b->nonce);
    unsigned char *hash=SHA256((const unsigned char *)nonce,strlen(nonce),0);

    if (strcmp((const char *)hash,zeros)==0){ // STRCMP RENVOIE 0 si les deux chaînes sont égales (0 étant le booléen pour false..)
        return 1;
    }
    return 0;
}


void delete_block(Block *b){
    free(b->hash);
    free(b->previous_hash);
    CellProtected *tmp;
    while(b->votes!=NULL){
        tmp=b->votes->next;
        free(b->votes);
        b->votes=tmp;
    }
    free(b);
}


CellTree *create_node(Block *b){
    CellTree *cell=(CellTree *)malloc(sizeof(CellTree));
    cell->block=b;
    cell->father=NULL;
    cell->firstChild=NULL;
    cell->nextBro=NULL;
    cell->height=0;

    return cell;
}

int update_height(CellTree *father,CellTree *child){
    int maximum=fmax(father->height,child->height+1);
    if (maximum==father->height){
        return 0;
    }
    father->height=maximum;
    return 1;
}

void add_child(CellTree *father,CellTree *child){
    // Ajout en tête du fils
    child->nextBro=father->firstChild;
    father->firstChild=child;

    // Modification de la hauteur des parents
    CellTree *ftmp=father;
    CellTree *ctmp=father->firstChild;
    while (ftmp!=NULL){
        update_height(ftmp,ctmp);
        ftmp=ftmp->father;
        ctmp=ctmp->father;
    }
}

/* Fonction d'affichage d'un arbre
--  ATTENTION : PROF DOIT ETRE APPELE AVEC LA VALEUR 0*/
void print_tree(CellTree *racine,int prof){
    if (racine==NULL){
        return;
    }
    char tabs[racine->height];
    CellTree *cour=racine;
    memset(tabs,'\t',prof);
    while (cour!=NULL){
        printf("%sHauteur:%s Hash:%s\n",tabs,cour->block->hash);
        print_tree(cour->firstChild,++prof);
        cour=cour->nextBro;
    }
}


void delete_node(CellTree *node){
    delete_block(node->block);
    free(node);
}

void delete_tree(CellTree *tree){
    CellTree *child=tree->firstChild;
    CellTree *tmp;
    while (child!=NULL){
        tmp=child->nextBro;
        delete_tree(child);
        child=tmp;
    }
    delete_node(child);
}

CellTree *highest_child(CellTree *cell){
    if (cell->firstChild==NULL){
        return NULL;
    }
    CellTree *child=cell->firstChild->nextBro;
    CellTree *max=cell->firstChild;
    while (child !=NULL){
        if (max->height<child->height){
            max=child;
        }
        child=child->nextBro;
    }
    return max;
}

CellTree *last_node(CellTree *tree){
    if (tree->firstChild==NULL){
        return tree;
    }
    return last_node(highest_child(tree));
}

void fusion_cell_protected(CellProtected **first, CellProtected **second){
    if (first==NULL){
        first=second;
        return;
    }
    CellProtected *tmp=first;
    while(tmp->next!=NULL){
        tmp=tmp->next;
    }
    tmp->next=second;
}


CellProtected *fusion_highest_CP(CellTree *racine){
    CellProtected *res=racine->block->votes;
    CellProtected *tmp=racine->block->votes;
    while ((tmp!=NULL) && (tmp->next!=NULL)){
        tmp=tmp->next;
    }
    CellTree *cour=highest_child(racine);


    while (cour!=NULL){
        fusion_cell_protected(tmp,cour->block->votes);
        cour=highest_child(racine);
        while ((tmp!=NULL) && (tmp->next!=NULL)){
            tmp=tmp->next;
        }
    }
    return res;
}