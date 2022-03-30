#include "list_data.h"
#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "winner.h"


HashCell *create_hashcell(Key *key){
    HashCell *res=(HashCell *)malloc(sizeof(HashCell));
    res->key=key;
    res->val=0;
    return res;
}

int hash_function(Key *key,int size){
    return (key->val+key->n)%size;
}


int find_position(HashTable *t,Key *key){
    HashCell* *tab=t->tab; 
    for(int i=0;i<t->size;i++){
        if (tab[i]!=NULL && tab[i]->key==key){
            return i;
        }
    }
    return hash_function(key,t->size);
}

HashTable *create_hashtable(CellKey *keys,int size){
    HashTable *table=(HashTable *)malloc(sizeof(HashTable));
    table->size=size;
    table->tab=(HashCell **)malloc(sizeof(HashCell *)*size);
    for(int i=0;i<size;i++){ // Initialisation des éléments à NULL (étant donné que ce n'est pas le cas automatiquement)
        table->tab[i]=NULL;
    }
    while (keys!=NULL){
        int hash=hash_function(keys->data,size);
        if (table->tab[hash]!=NULL){
            for(int i=0;i<size;i++){
                if(table->tab[(hash+i)%size]!=NULL){
                    table->tab[(hash+i)%size]=create_hashcell(keys->data);
                    break;
                }
            }
        } else {
            table->tab[hash]=create_hashcell(keys->data);
        }
        keys=keys->next;
    }

    return table;
}

void delete_hashtable(HashTable *t){
    for(int i=0;i<t->size;i++){
        if (t->tab[i]!=NULL){
            free(t->tab[i]->key);
            free(t->tab[i]);
        }

    }
    free(t->tab);
    free(t);
}

int verif_declaration(Protected *decl,CellKey *list){

    while (list!=NULL){
        if (decl->pKey->val==list->data->val && decl->pKey->n==list->data->n){
            return 0;
        }
        list=list->next;
    }
    return -1;
}
int verif_candidat(Key *cand,CellKey *list){
    while (list!=NULL){
        //printf("Valeur :%ld\n",cand->val);
        if (cand->val==list->data->val && cand->n==list->data->n){
            return 0;
        }
        list=list->next;
    }
    return -1;
}

Key *compute_winner(CellProtected *decl,CellKey *candidates,CellKey *voters,int sizeC,int sizeV){
    if (voters==NULL || candidates==NULL || decl==NULL){
        return NULL;
    }
    HashTable *tableC=create_hashtable(candidates,sizeC);
    HashTable *tableV=create_hashtable(voters,sizeV);
    CellProtected *declarations=decl;
    while(declarations!=NULL){
        
        if (verif_declaration(declarations->data,voters)==0){
            
            if (tableV->tab[find_position(tableV,declarations->data->pKey)]->val==0){
                //printf("aJAJKA\n");
                tableV->tab[find_position(tableV,declarations->data->pKey)]->val=1;
                Key *ck=str_to_key(declarations->data->mess);
                if (verif_candidat(ck,candidates)){
                    tableC->tab[find_position(tableC,ck)]->val++;
                }
                free(ck);
            }
        }
        declarations=declarations->next;
    }
    HashCell *max=NULL;
    for(int i=0;i<sizeC;i++){
        if (tableC->tab[i]!=NULL){
            max=tableC->tab[i];
            break;
        }
    }
    for(int i=1;i<sizeC;i++){
        if (tableC->tab[i]!=NULL && tableC->tab[i]->val > max->val){
            max=tableC->tab[i];
        }
    }
    delete_hashtable(tableC);
    delete_hashtable(tableV);
    return max->key;
}


int main(){


    CellKey *voters=read_public_keys("keys.txt");
    HashTable *table=create_hashtable(voters,50);
    CellKey *candidates=read_public_keys("candidates.txt");
    int pos=find_position(table,voters->next->data);
    HashCell *cell=create_hashcell(voters->data);
    int sizeV=50;
    int sizeC=20;
    CellProtected *decl=valid_list_protected(read_protected("declarations.txt"));
    //verif_candidat(candidates->data,voters);
    Key *winner=compute_winner(decl,candidates,voters,sizeC,sizeV);
    char *winnerstr=key_to_str(winner);
    printf("Winner : %s\n",winnerstr);
    delete_hashtable(table);

    return 0;
}