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
#include <dirent.h> 
#include "winner.h"

/*Fonction de sauvegarde d'un bloc dans un fichier <filename>
Structure du fichier:
|AUTHOR| |PREVIOUS HASH| |HASH| |NONCE|
|CELLPROTECTED|
|CELLPROTECTED|
|CELLPROTECTED|
.
.
.
*/
void save_block(Block *b,char *filename){
    FILE *f=fopen(filename,"w");
    CellProtected *cp=b->votes;
    char *kstr=key_to_str(b->author);
    char *pstr=NULL;

    fprintf(f,"%s %s %s %d\n",kstr,b->previous_hash,b->hash,b->nonce);
    free(kstr);

    while (cp!=NULL){
        pstr=protected_to_str(cp->data);
        fprintf(f,"%s\n",pstr);
        free(pstr);
        cp=cp->next;
    }
    fclose(f);
}

/*Fonction de lecture d'un block enregistré dans un fichier
Structure du fichier demandé:
|AUTHOR| |PREVIOUS HASH| |HASH| |NONCE|
|CELLPROTECTED|
|CELLPROTECTED|
|CELLPROTECTED|
.
.
.
*/
Block *read_block(char *filename){
    FILE *f=fopen(filename,"r");
    if (f==NULL){
        printf("ERREUR OUVERTURE FICHIER -- READ_BLOCK\n");
        exit(-1);
    }
    Block *b=(Block *)malloc(sizeof(Block));
    b->hash=(unsigned char *)malloc(sizeof(unsigned char)*256);
    b->previous_hash=(unsigned char *)malloc(sizeof(unsigned char)*256);
    if (b==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    char kstr[256];
    char pstr[512];
    b->votes=NULL;
    char buffer[512];
    fgets(buffer,512,f);
    sscanf(buffer,"%s %s %s %d",kstr,b->previous_hash,b->hash,&(b->nonce));
    b->author=str_to_key(kstr);
    // On a besoin d'éviter l'inversion des ajouts en tête
    // Donc on n'utilise pas add_head_cellprotected
    if (fgets(buffer,512,f)!=NULL){ // Premier élément 
        sscanf(buffer,"%s\n",pstr);
        b->votes=create_cell_protected(str_to_protected(buffer));
        CellProtected *lastelement=b->votes;
        while (fgets(buffer,512,f)!=NULL){ // Elements suivants
            sscanf(buffer,"%s\n",pstr);
            lastelement->next=create_cell_protected(str_to_protected(buffer));
            lastelement=lastelement->next;
        }
    }


    fclose(f);
    return b;
}

char *block_to_str(Block *block){
    char *res=(char *)malloc(sizeof(char)*1024);
    char *ctmp=(char *)malloc(sizeof(char)*256);
    if (res==NULL || ctmp==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    char *key=key_to_str(block->author);
    ctmp[0]='\0';
    char *cpstrtmp;
    CellProtected *tmp=block->votes;
    while (tmp!=NULL){
        cpstrtmp=protected_to_str(tmp->data);
        strcat(cpstrtmp,"\n");
        ctmp=(char *)realloc(ctmp,strlen(ctmp)+128*sizeof(char));
        strcat(ctmp,cpstrtmp);
        free(cpstrtmp);
        tmp=tmp->next;
    }
    res=realloc(res,strlen(ctmp)+256*sizeof(char));
    sprintf(res,"%s %s\n%s%d",key,block->previous_hash,ctmp,block->nonce);
    free(key);
    free(ctmp);
    return res;
}

/*Exactement pareil que block_to_str mais sans le nonce
-- Question d'optimisations pour compute_proof_of_work*/
char *block_to_str_bis(Block *block){
    char *res=(char *)malloc(sizeof(char)*1024);
    char *ctmp=(char *)malloc(sizeof(char)*256);
    if (res==NULL || ctmp==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    char *key=key_to_str(block->author);
    ctmp[0]='\0';
    char *cpstrtmp;
    CellProtected *tmp=block->votes;
    while (tmp!=NULL){
        cpstrtmp=protected_to_str(tmp->data);
        strcat(cpstrtmp,"\n");
        ctmp=(char *)realloc(ctmp,strlen(ctmp)+128*sizeof(char));
        strcat(ctmp,cpstrtmp);
        free(cpstrtmp);
        tmp=tmp->next;
    }
    res=realloc(res,strlen(ctmp)+256*sizeof(char));
    sprintf(res,"%s %s\n%s",key,block->previous_hash,ctmp);
    free(key);
    free(ctmp);
    return res;
}
/*Fonction de hachage avec protocole SHA256
-- Retour : Chaîne de caractères et non valeurs hexadécimales*/
unsigned char *func_sha(const char *str){
    unsigned char *res=(unsigned char *)malloc(sizeof(char)*256);
    if (res==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    unsigned char *d=SHA256((unsigned char *)str,strlen(str),0);
    // J'évite les boucles for ici pour ne avoir à appeler qu'une seule fois sprintf au lieu d'appeler 32 fois sprintf et strcat
    sprintf((char *)res,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15],d[16],d[17],d[18],d[19],d[20],d[21],d[22],d[23],d[24],d[25],d[26],d[27],d[28],d[29],d[30],d[31]);
    return res;
}

/*Fonction de recherche d'une valeur hachée du bloc commençant avec d zéros
-- Résultats appliqués à b->nonce et b->hash*/
void compute_proof_of_work(Block *b,int d){
    unsigned char *hash;
    char zeros[d+1];
    memset(zeros,'0',d);
    zeros[d]='\0';
    char *block=block_to_str_bis(b);
    char tohash[strlen(block)+sizeof(int)+2];
    char *hashcomp;
    for(int i=0;i<INT32_MAX;i++){
        b->nonce=i;
        sprintf(tohash,"%s%d",block,i);
        hash=func_sha(tohash);
        hashcomp=strdup((char *)hash);
        hashcomp[d]='\0';
        if (strcmp((const char *)hashcomp,zeros)==0){
            printf("%s %d ---- VALIDE !\n",hash,i);
            b->hash=hash;
            b->nonce=i;
            free(block);
            free(hashcomp);
            return;
        }
        free(hashcomp);
        free(hash);
    }
    b->nonce=-1;
    printf("On a rien trouvé\n");
}


/*Fonction de vérification d'un bloc
-- Vérifie que la valeur hachée du bloc commence par d nombre de zéros*/
int verify_block(Block *b,int d){
    char zeros[d+1];
    char *blockstr=block_to_str(b);
    memset(zeros,'0',d);
    zeros[d]='\0';
    unsigned char *hash=func_sha(blockstr);
    hash[d]='\0';
    if (strcmp((const char *)hash,zeros)==0){ // STRCMP RENVOIE 0 si les deux chaînes sont égales (0 étant le booléen pour false..)
        free(blockstr);
        free(hash);
        return 1;
        
    }
    free(hash);
    free(blockstr);
    return 0;
}

/*Fonction de création d'un bloc
-- Informations obtenues à partir du fichier Pending_votes.txt
-- Bloc sauvegardé dans le fichier Pending_block*/
void create_block(CellTree **tree,Key *author,int d){
    Block *b=(Block *)malloc(sizeof(Block));

    if (b==NULL){
        printf("ERREUR ALLOCATION MALLOC -- CREATE_BLOCK\n");
        exit(-1);
    }

    CellProtected *plist=read_protected("Blockchain/Pending_votes.txt"); 
    CellTree *lastnode=last_node(*tree);
    
    b->author=author;
    b->votes=plist;
    if (lastnode==NULL){
        b->previous_hash=NULL;
        *tree=create_node(b);
    } else {
        b->previous_hash=(unsigned char *)strdup((char *)lastnode->block->hash);
    }
    
    compute_proof_of_work(b,d);
    CellTree *cell=create_node(b);
    add_child(lastnode,cell);
    save_block(b,"Blockchain/Pending_block");
    remove("Blockchain/Pending_votes.txt");
}

/*Fonction de suppression d'un bloc*/
void delete_block(Block *b){

    if (b==NULL){
        return;
    }
    if (b->hash!=NULL){
        free(b->hash);
    }
    
    if (b->previous_hash!=NULL){
        free(b->previous_hash);
    }
    CellProtected *tmp;
    while(b->votes!=NULL){
        tmp=b->votes->next;
        free(b->votes);
        b->votes=tmp;
    }
    free(b);
}

/*Fonction d'ajout d'un bloc dans le dossier Blockchain
-- Le bloc ajouté est dans le fichier Pending_block*/
void add_block(int d,char *name){
    Block *b=read_block("Blockchain/Pending_block");
    if (verify_block(b,d)==1){
        save_block(b,name);
    }

    delete_list_protected(b->votes);
    b->votes=NULL;
    free(b->author);
    delete_block(b);
    remove("Blockchain/Pending_block");
}

/*Fonction de soumission d'un vote
-- Le vote est ajouté à la fin du fichier Pending_votes.txt*/
void submit_vote(Protected *p){
    FILE *f=fopen("Blockchain/Pending_votes.txt","a");
    if (f==NULL){
        printf("ERREUR ECRITURE DE FICHIER -- SUBMIT_VOTES\n");
        exit(-1);
    }
    char *pstr=protected_to_str(p);
    fprintf(f,"%s\n",pstr);
    free(pstr);
    fclose(f);
}

// ---------------------------------------------------------------------
// -------------------------- Arbres de blocs --------------------------
// ---------------------------------------------------------------------




/*Fonction de création d'un noeud*/
CellTree *create_node(Block *b){
    CellTree *cell=(CellTree *)malloc(sizeof(CellTree));
    if (cell==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    cell->block=b;
    cell->father=NULL;
    cell->firstChild=NULL;
    cell->nextBro=NULL;
    cell->height=0;

    return cell;
}

/*Fonction de mise à jour de la hauteur du noeud father*/
int update_height(CellTree *father,CellTree *child){
    int maximum=fmax(father->height,child->height+1);
    if (maximum==father->height){
        return 0;
    }
    father->height=maximum;
    return 1;
}

/*Fonction d'ajout d'un noeud fils child au noeud père father*/
void add_child(CellTree *father,CellTree *child){
    if (father==NULL){
        father=child;
        return;
    }
    // Ajout du fils
    if (father->firstChild==NULL){
        father->firstChild=child;
    } else {
        CellTree *tmp=father->firstChild;
        while (tmp->nextBro != NULL) {
          tmp=tmp->nextBro;
        }
        tmp->nextBro = child;
    }
    child->father=father;

    // Modification de la hauteur des parents
    CellTree *ftmp=father;
    CellTree *ctmp=father->firstChild;
    while (ftmp!=NULL){
        update_height(ftmp,ctmp);
        ctmp=ftmp;
        ftmp=ftmp->father;
    }
}

/* Fonction d'affichage d'un arbre
--  ATTENTION : PROF DOIT ETRE APPELE AVEC LA VALEUR 0*/
void print_tree(CellTree *racine,int prof){
    if (racine==NULL){
        return;
    }
    char tabs[prof+1];
    CellTree *cour=racine;
    memset(tabs,' ',prof);
    tabs[prof]='\0';

    printf("%sHauteur:%d Hash:%s\n",tabs,cour->height,cour->block->hash);
    print_tree(cour->firstChild,prof+1);
    print_tree(cour->nextBro,prof);
}

/*Fonction de suppression d'un noeud*/
void delete_node(CellTree *node){
    if (node==NULL){
        return;
    }
    if (node->block!=NULL){
        delete_block(node->block);
    }
    free(node);
}

/*Fonction de suppression d'un arbre*/
void delete_tree(CellTree *tree){
    if (tree==NULL){
        return;
    }

    delete_tree(tree->firstChild);
    delete_tree(tree->nextBro);
    delete_node(tree);

}

/*Fonction de recherche de l'enfant possèdant la hauteur la plus élevée*/
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

/*Fonction de recherche du noeud ayant le parcours le plus long*/
CellTree *last_node(CellTree *tree){
    if (tree==NULL){
        return NULL;
    }
    if (tree->firstChild==NULL){
        return tree;
    }
    return last_node(highest_child(tree));
}


/*Fonction de fusion des listes de déclaration contenues dans la plus longue chaîne d'éléments
-- Amélioration dans le parcours résultat 
O(2^n) environ => O(n)  */
CellProtected *fusion_highest_CP(CellTree *racine){
    CellProtected *res=racine->block->votes;
    CellProtected *tmp=racine->block->votes;
    while ((tmp!=NULL) && (tmp->next!=NULL)){
        tmp=tmp->next;
    }
    CellTree *cour=highest_child(racine);


    while (cour!=NULL){
        fusion_cell_protected(&tmp,cour->block->votes);
        cour=highest_child(racine);
        while ((tmp!=NULL) && (tmp->next!=NULL)){
            tmp=tmp->next;
        }
    }
    return res;
}

/*Fonction de lecture du dossier Blockchain pour créer un arbre de blocs
-- Retourne la racine de l'arbre*/
CellTree *read_tree(){
    // Recherche du nombre de fichiers dans le dossier Blockchain
    // Possible de faire un seul parcours du dossier et avoir un tableau à taille variable (realloc)
    int c=0;
    DIR *repc=opendir("./Blockchain/");
    if (repc !=NULL){
        struct dirent *dir;
        while ((dir=readdir(repc))){
            if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
                c++;
            }
        }
        closedir(repc);
    }

    // Création des blocs
    CellTree *tab[c];
    CellTree *racine=NULL;
    int maxi=0;
    DIR *rep=opendir("./Blockchain/");
    char filename[1080]; // Implique une taille maximale de nom de fichier
    if (rep!=NULL){
        struct dirent *dir;
        while ((dir=readdir(rep))){
            if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
                sprintf(filename,"Blockchain/%s",dir->d_name);
                tab[maxi]=create_node(read_block(filename));
                maxi++;
            }
        }
        closedir(rep);
    }
    // Recherche des liens père/fils
    for(int i=0;i<maxi;i++){
        for(int j=0;j<maxi;j++){
            if (j==i){
                continue;
            }
            if (strcmp((char *)tab[j]->block->previous_hash,(char *)tab[i]->block->hash)==0){
                add_child(tab[i],tab[j]);
            }
        }
    }
    // Recherche de la racine
    for(int k=0;k<maxi;k++){
        if (tab[k]->father==NULL){
            racine=tab[k];
        }
    }
    return racine;
} 

Key *compute_winner_BT(CellTree *tree,CellKey *candidates,CellKey *voters,int sizeC,int sizeV){
    CellTree *tmp=tree;
    CellProtected *list=NULL;
    while (tmp!=NULL){      
        fusion_cell_protected(&list,tmp->block->votes);
        tmp=highest_child(tmp);
    }
    CellProtected *vlist=valid_list_protected(list);
    return compute_winner(vlist,candidates,voters,sizeC,sizeV);
}