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

    while(LCK){
        printf("%s\n",key_to_str(LCK->data));
        printf("\n");
        LCK=LCK->next;
    }
}
/*Fonction de création d'un élément CellKey*/
CellKey *create_cell_key(Key *key){
    CellKey *cell=(CellKey *)malloc(sizeof(CellKey));
    cell->data=key;
    cell->next=NULL;
    return cell;
}
/*Fonction de création d'un élément CellProtected*/
CellProtected *create_cell_protected(Protected *pr){
    CellProtected *cell=(CellProtected *)malloc(sizeof(CellProtected));
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
        printf("ERREUR DE LECTURE\n");
        return NULL;
    }
    char buffer[256];
    CellKey *list=NULL;
    Key *key;
    long val,n;
    while(fgets(buffer,256,f)!=NULL){
        key=(Key *)malloc(sizeof(Key));
        sscanf(buffer,"(%lx,%lx)",&val,&n);
        init_key(key,val,n);
        list=add_head_cellkey(list,key);
    }
    fclose(f);
    print_list_keys(list);
    return list;
}
/*Fonction de suppression d'un cellule de liste de clés (CellKey)*/
void delete_cell_key(CellKey *c){
    if (c==NULL){
        return;
    }
    free(c->data);
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
    while(LCP!=NULL){
        str=protected_to_str(LCP->data);
        printf("%s\n",str);
        free(str);
        LCP=LCP->next;
    }
}
/* Fonction de lecture de keys.txt et declarations.txt pour créer une liste de déclarations (CellProtected)*/
CellProtected *read_protected(){
    FILE *f1=fopen("declarations.txt","r");
    FILE *f2=fopen("keys.txt","r");
    if (f1==NULL && f2==NULL){
        printf("ERREUR DE LECTURE\n");
        return NULL;
    } 
    char buffer1[512];
    char buffer2[512];
    CellProtected *list=NULL;
    // Variables pour la déclaration
    Protected *element=NULL;
    // Variables pour la signature
    Signature *sgn=NULL;
    char crypted[256];
    // Variables pour la clé
    Key *key=NULL;
    long pval,pn,sval,sn;
    while((fgets(buffer1,512,f1)!=NULL) && (fgets(buffer2,512,f2)!=NULL)){
        // Lecture des fichiers
        sscanf(buffer1,"%s",crypted);
        sscanf(buffer2,"(%lx,%lx) (%lx,%lx)",&pval,&pn,&sval,&sn);
        // Allocation des éléments courants
        key=(Key *)malloc(sizeof(Key));
        sgn=str_to_signature(crypted);
        // Déclaration des éléments courants
        init_key(key,pval,pn);

        element=init_protected(key,decrypt(sgn->tab,sgn->n,pval,pn),sgn);
        // Ajout de l'élément dans la liste
        list=add_head_cellprotected(list,element);
    }
    fclose(f1);
    fclose(f2);
    return list;
}


/*Fonction de suppression d'une cellule CellProtected*/
void delete_cell_protected(CellProtected *c){
    if (c==NULL){
        return;
    }
    free(c->data->mess);
    free(c->data->pKey);
    free(c->data->sgn->tab);
    free(c->data->sgn);
    free(c->data);
    free(c);
}

/*Fonction de suppression d'une liste de CellProtected*/
void delete_list_protected(CellProtected *list){
    CellProtected *tmp;
    while (list!=NULL){
        tmp=list->next;
        //free(list->data->mess);
        delete_cell_protected(list);
        list=tmp;
    }
}


/* Fonction retirant toutes les déclarations non valides (Fausses signatures)*/
CellProtected *valid_list_protected(CellProtected *list){
    CellProtected *prec;
    CellProtected *cour;
    CellProtected *tmp;
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

/*Main provisoire pour tester le fonctionnement des fonctions ci-dessus et analyse des fuites mémoires*/
int main(){

    //CellKey *list=read_public_keys("keys.txt");
    CellProtected *list=read_protected();
    //printf("%s\n",decrypt(plist->data->sgn->tab,plist->data->sgn->n,2633,2867));
    sprintf(list->next->next->next->data->mess,"9cb)");
    list=valid_list_protected(list);
    
    printf("\n\n");
    //print_list_protected(list);
    delete_list_protected(list);
}