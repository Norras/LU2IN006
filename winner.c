#include "list_data.h"
#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "winner.h"

/*Fonction de création d'une cellule de table de hachage
-- Stocke une clé et une valeur entière*/
HashCell *create_hashcell(Key *key){
    HashCell *res=(HashCell *)malloc(sizeof(HashCell));
    if (res==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    res->key=key;
    res->val=0;
    return res;
}
/*Fonction de hachage de la clé
-- Calcul pour une clé (u,n) : (u+n)%size*/
int hash_function(Key *key,int size){
    return (key->val+key->n)%size;
}

/*Fonction déterminant la position d'une clé dans une table de hachage
-- Si l'élément n'est pas dans la table,la fonction renvoie la position que devrait avoir la clé dans la table grâce à hash_function*/
int find_position(HashTable *t,Key *key){
    HashCell* *tab=t->tab; 
    for(int i=0;i<t->size;i++){
        if (tab[i]!=NULL && tab[i]->key==key){
            return i;
        }
    }
    return hash_function(key,t->size);
}


/*Fonction de création d'une table de hachage à partir d'une liste de clés*/
HashTable *create_hashtable(CellKey *keys,int size){
    HashTable *table=(HashTable *)malloc(sizeof(HashTable));
    if (table==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    table->size=size;
    table->tab=(HashCell **)malloc(sizeof(HashCell *)*size);
    if (table->tab==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    for(int i=0;i<size;i++){ // Initialisation des éléments à NULL (étant donné que ce n'est pas le cas automatiquement)
        table->tab[i]=NULL;
    }
    while (keys!=NULL){
        int hash=hash_function(keys->data,size);
        if (table->tab[hash]!=NULL){
            for(int i=0;i<size;i++){
                if(table->tab[(hash+i)%size]==NULL){
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

/*Fonction de suppression d'une table de hachage en mémoire
-- Aucune suppression de clé n'est faite, faites appel à delete_list_keys pour cela*/
void delete_hashtable(HashTable *t){
    for(int i=0;i<t->size;i++){
        if (t->tab[i]!=NULL){
            free(t->tab[i]);
        }
    }
    free(t->tab);
    free(t);
}

/*Fonction pour compute_winner
--Vérifie l'occurence de la clé cand dans la liste list
-- Renvoie 1 si occurence il y a,0 sinon*/
int occurence_key(Key *key,CellKey *list){
    while (list!=NULL){
        //printf("Valeur :%ld\n",cand->val);
        if (key->val==list->data->val && key->n==list->data->n){
            return 1;
        }
        list=list->next;
    }
    return 0;
}

/*Fonction déterminant le gagnant des élections
-- Renvoie la clé avec le plus d'occurence dans la liste declarations
-- Vérifie si les clés dans les déclarations est stockée dans la liste candidates
-- Vérifie si la clé publique de la déclaration est stockée dans la liste voters*/
Key *compute_winner(CellProtected *decl,CellKey *candidates,CellKey *voters,int sizeC,int sizeV){
    if (voters==NULL || candidates==NULL || decl==NULL){
        return NULL;
    }
    HashTable *tableC=create_hashtable(candidates,sizeC);
    HashTable *tableV=create_hashtable(voters,sizeV);
    CellProtected *declarations=decl;
    while(declarations!=NULL){
        
        if (occurence_key(declarations->data->pKey,voters)){
            
            if (tableV->tab[find_position(tableV,declarations->data->pKey)]->val==0){ // Est-ce que l'électeur n'a pas voté ?
                tableV->tab[find_position(tableV,declarations->data->pKey)]->val=1;
                Key *ck=str_to_key(declarations->data->mess);
                if (occurence_key(ck,candidates)){ // Est-ce que le candidat est légitime ?
                    tableC->tab[find_position(tableC,ck)]->val++;
                }
                free(ck);
            }
        }
        declarations=declarations->next;
    }
    HashCell *max=NULL;
    for(int i=0;i<sizeC;i++){ // Recherche du premier élément HashCell non nul pour initialiser le max
        if (tableC->tab[i]!=NULL){
            max=tableC->tab[i];
            break;
        }
    }
    for(int i=1;i<sizeC;i++){ // Comparaison des nombres d'occurences pour déterminer le max
        if (tableC->tab[i]!=NULL && tableC->tab[i]->val > max->val){
            max=tableC->tab[i];
        }
    }
    Key *res=(Key *)malloc(sizeof(Key));
    if (res==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    init_key(res,max->key->val,max->key->n);
    delete_hashtable(tableC);
    delete_hashtable(tableV);
    
    return res;
}


