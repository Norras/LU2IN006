#include "list_data.h"
#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/*Fonction d'affichage d'un tableau de long*/
void print_long_vector(long *result,int size){
    printf("Vector: [");
    for(int i=0;i<size;i++){
        printf("%lx \t",result[i]);
    }
    printf("]\n");
}
/*Fonction d'affichage d'une liste de clés*/
void print_list_keys(CellKey *LCK){
    char *str;
    CellKey *tmp=LCK;
    while(tmp){
        str=key_to_str(tmp->data);
        printf("%s\n",str);
        free(str);
        tmp=tmp->next;
    }
}
/*Fonction de création d'un élément CellKey*/
CellKey *create_cell_key(Key *key){
    CellKey *cell=(CellKey *)malloc(sizeof(CellKey));
    if (cell==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    cell->data=key;
    cell->next=NULL;
    return cell;
}
/*Fonction de création d'un élément CellProtected*/
CellProtected *create_cell_protected(Protected *pr){
    CellProtected *cell=(CellProtected *)malloc(sizeof(CellProtected));
    if (cell==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    cell->data=pr;
    cell->next=NULL;
    return cell;
}
/*Fonction d'ajout d'une clé (Key) dans une liste de clés (CellKey)*/
CellKey *add_head_cellkey(CellKey *list,Key *key){
    CellKey *cell=create_cell_key(key);
    cell->next=list;
    return cell;
}
/*Fonction d'ajout en tête d'une déclaration (Protected) dans une liste de déclarations (CellProtected)*/
CellProtected *add_head_cellprotected(CellProtected *list,Protected *cpr){
    CellProtected *cell=create_cell_protected(cpr);
    cell->next=list;
    return cell;
}

/*Fonction de lecture de clés publiques
-- Les clés doivent être écrits tels que (%lx,%lx)
-- Une clé/paire de clés par ligne*/
CellKey *read_public_keys(char *fichier){
    FILE *f=fopen(fichier,"r");
    
    if (f==NULL){
        printf("ERREUR DE LECTURE,FIN DU PROGRAMME\n");
        exit(1);
    }
    char buffer[256];
    CellKey *list=NULL;
    Key *key;
    long val,n;
    while(fgets(buffer,256,f)!=NULL){
        key=(Key *)malloc(sizeof(Key));
        if (key==NULL){
            printf("ERREUR MALLOC\n");
            exit(-1);
        }
        sscanf(buffer,"(%lx,%lx)",&val,&n);
        init_key(key,val,n);
        list=add_head_cellkey(list,key);
    }
    fclose(f);
    return list;
}
/*Fonction de suppression d'un cellule de liste de clés (CellKey)*/
void delete_cell_key(CellKey *c){
    if (c==NULL){
        return;
    }
    if (c->data!=NULL){
        free(c->data);
    }
    free(c);
}
/*Fonction de suppression de liste de clés (CellKey)*/
void delete_list_keys(CellKey *list){
    CellKey *tmp;
    while(list){
        tmp=list->next;
        delete_cell_key(list);
        list=tmp;
    }
}
/*Fonction d'affichage de liste de déclarations (CellProtected)*/
void print_list_protected(CellProtected *LCP){
    char *str;
    CellProtected *tmp=LCP;
    while(tmp!=NULL){
        str=protected_to_str(tmp->data);
        printf("%s\n",str);
        free(str);
        tmp=tmp->next;
    }
}
/* Fonction de lecture de keys.txt et declarations.txt pour créer une liste de déclarations (CellProtected)*/
CellProtected *read_protected(char *filename){
    FILE *f=fopen(filename,"r");
    if (f==NULL){
        printf("ERREUR DE LECTURE,FIN DU PROGRAMME\n");
        exit(1);
    }
    // Création des tableaux locaux pour la récupération des éléments
    char buffer[512];
    char keystring[256];
    char mess[256];
    char crypted[256];
    // Création des éléments de structures pour créer un élément CellProtected
    Key *pKey=NULL;
    Signature *sgn=NULL;
    Protected *p=NULL;
    CellProtected *list=NULL;
    while (fgets(buffer,512,f)!=NULL){
        sscanf(buffer,"%s %s %s",keystring,mess,crypted);
        pKey=str_to_key(keystring);
        sgn=str_to_signature(crypted);
        p=init_protected(pKey,strdup(mess),sgn);
        list=add_head_cellprotected(list,p);
    }
    fclose(f);
    return list;
}

/*Fonction de suppression d'une cellule CellProtected*/
void delete_cell_protected(CellProtected *c){
    if (c==NULL){
        return;
    }
    free_protected(c->data);
    free(c);
}

/*Fonction de suppression d'une liste de CellProtected*/
void delete_list_protected(CellProtected *list){
    CellProtected *tmp;
    while (list!=NULL){
        tmp=list->next;
        delete_cell_protected(list);
        list=tmp;
    }
}

/* Fonction retirant toutes les déclarations non valides (Fausses signatures)*/
CellProtected *valid_list_protected(CellProtected *list){
    CellProtected *prec=NULL;
    CellProtected *cour=NULL;
    CellProtected *tmp=NULL;
    if (verify(list->data)!=0){
        tmp=list;
        list=list->next;
        delete_cell_protected(tmp);
        return valid_list_protected(list);
    }
    prec=list;
    cour=list->next;
    while (cour!=NULL){
        if (verify(cour->data)!=0){
            tmp=cour;
            cour=cour->next;
            prec->next=cour;
            delete_cell_protected(tmp);
        } else {
            prec=prec->next;
            cour=cour->next;
        }
    }
    return list;
}

/*Fonction de fusion de deux listes chaînées de CellProtected*/
void fusion_cell_protected(CellProtected **first, CellProtected *second){
    if (*first==NULL){
        *first=second;
        return;
    }
    CellProtected *tmp=*first;
    while(tmp->next!=NULL){
        tmp=tmp->next;
    }
    tmp->next=second;
}
