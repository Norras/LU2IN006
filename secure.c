#include "secure.h"
#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*Fonction d'initialisation d'une clé
-- key doit être instancié en amont*/
void init_key(Key *key,long val,long n){
    key->val=val;
    key->n=n;
}

/* Fonction d'initialisation de clés publiques/privées
-- pKey et sKey doivent être instanciés en amont */
void init_pair_keys(Key *pKey,Key *sKey,long low_size,long up_size){
    long n=0,s=0,u=0;
    while (s==u){
        generate_key_values(random_prime_number(low_size,up_size,5000),random_prime_number(low_size,up_size,5000),&n,&s,&u);
    }
    init_key(pKey,s,n);
    init_key(sKey,u,n);
}

/*Fonction de conversion d'une clé en chaine de caractères*/
char *key_to_str(Key *key){
    char *res=(char *)malloc(sizeof(char)*256);
    if (res==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    sprintf(res,"(%lx,%lx)",key->val,key->n);
    return res;
}

/*Fonction de conversion d'une chaine de caractères en clé*/
Key *str_to_key(char *str){
    Key *key=(Key *)malloc(sizeof(Key));
    if (key==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    sscanf(str,"(%lx,%lx)",&(key->val),&(key->n));
    return key;
}

/*Fonction d'initialisation d'une signature*/
Signature* init_signature(long* content, int size){
    Signature *res=(Signature *)malloc(sizeof(Signature));
    if (res==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    res->tab=content;
    res->n=size;
    return res;
}
/*Fonction de libération d'une signature*/
void free_signature(Signature *sgn){
    if (sgn==NULL){
        return;
    }
    if (sgn->tab!=NULL){
        free(sgn->tab);
    }
    free(sgn);
}
/*Fonction de création d'une signature
-- Fait appel à init_signature avec le message crypté et la clé secrète*/
Signature* sign(char* mess, Key* sKey){
    long *tab=encrypt(mess,sKey->val,sKey->n);
    Signature *res=init_signature(tab,strlen(mess));
    return res;
}

/*Fonction de conversion d'une signature en chaine de caractères*/
char *signature_to_str(Signature * sgn ) {
    char *result=malloc(10*sgn->n*sizeof(char));
    if (result==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    result[0]= '#';
    int pos = 1;
    char buffer[256];
    for ( int i=0; i < sgn->n; i++) {
        sprintf(buffer,"%lx",sgn->tab[i]) ;
        for (int j=0; j < strlen(buffer);j++) {
            result[pos]=buffer[j];
            pos=pos+1;
        }
        result[pos]='#';
        pos=pos+1;
    }
    result[pos]='\0';
    result=realloc(result,(pos+1)*sizeof(char));
    return result;
}

/*Fonction de conversion d'une chaine de caractères en signature*/
Signature *str_to_signature(char *str){
    int len=strlen(str);
    long *content=(long *)malloc(sizeof(long)*len);
    if (content==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    int num=0;
    char buffer[256];
    int pos=0;
    for(int i=0;i<len;i++){
        if (str[i]!='#'){
            buffer[pos]=str[i];
            pos++;
        } else {
            if (pos !=0){
                buffer[pos]='\0';
                sscanf(buffer,"%lx",&(content[num]));
                num++;
                pos=0;
            }
        }
    }
    content=realloc(content,num*sizeof(long));
    return init_signature(content,num);
}
/*Fonction d'initialisation d'un élément Protected (Déclaration signée)*/
Protected* init_protected(Key* pKey, char* mess, Signature* sgn){
    Protected *res=(Protected *)malloc(sizeof(Protected));
    if (res==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    res->pKey=pKey;
    res->mess=mess;
    res->sgn=sgn;
    return res;
}

void free_protected(Protected *p){
    if (p==NULL){
        return;
    }
    if (p->pKey!=NULL){
        free(p->pKey);
    }
    if (p->mess!=NULL){
        free(p->mess);
    }
    free_signature(p->sgn);
    free(p);
}

/*Fonction de vérification du message chiffré avec la clé publique*/
int verify(Protected *pr){
    char *t=decrypt(pr->sgn->tab,pr->sgn->n,pr->pKey->val,pr->pKey->n);
    char dc[500];
    strcpy(dc,t);
    free(t);
    return strcmp(pr->mess,dc);
}

/*Fonction de conversion d'une structure Protected en chaine de caractères*/
char *protected_to_str(Protected *pr){
    if (pr==NULL){
        return "";
    }
    char *res=malloc(sizeof(char)*512);
    if (res==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    char *k=key_to_str(pr->pKey);
    char *s=signature_to_str(pr->sgn);
    sprintf(res,"%s %s %s",k,pr->mess,s);
    free(k);
    free(s);
    return res;
}

/*Fonction de conversion d'une chaine de caractères en structure Protected (Déclaration signée)*/
Protected *str_to_protected(char *str){
    char k[256];
    char *m=malloc(sizeof(char)*256);
    if (m==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
    char s[256];
    s[0]='\0';
    sscanf(str,"%s %s %s",k,m,s);
    Protected *p=init_protected(str_to_key(k),m,str_to_signature(s));
    return p;
}

/*Fonction pour generate_random_data
-- Empêche la redondance de candidats dans candidates.txt
-- Renvoie 1 si occurence il y a,0 sinon*/
int occurence_int(int val,int *tab,int size){
    for(int i=0;i<size;i++){
        if (val==tab[i]){
            return 1;
        }
    }
    return 0;
}
/*Fonction de création de données d'élections
-- Les données sont stockés dans les fichiers keys.txt,candidates.txt et declarations.txt*/
void generate_random_data(int nv,int nc){
    FILE *keys=fopen("keys.txt","w");
    FILE *candidates=fopen("candidates.txt","w");
    FILE *declarations=fopen("declarations.txt","w");
    Key *kptab[nv];
    Key *kstab[nv];
    Key *cptab[nc];
    int nonocc[nc];
    char *mess;
    char *str;
    char *str2;
    int rdm;
    Signature *sgn;
    // Ecriture du fichier keys.txt
    for(int i=0;i<nv;i++){
        kptab[i]=(Key *)malloc(sizeof(Key));
        kstab[i]=(Key *)malloc(sizeof(Key));
        if (kptab[i]==NULL || kstab[i]==NULL){
        printf("ERREUR MALLOC\n");
        exit(-1);
    }
        init_pair_keys(kptab[i],kstab[i],3,7);
        str=key_to_str(kstab[i]);
        str2=key_to_str(kptab[i]);
        fprintf(keys,"%s %s\n",str2,str);
        free(str);
        free(str2);
    }
    // Ecriture du fichier candidates.txt
    for(int i=0;i<nc;i++){
        srand(time(NULL)*rand());
        rdm=rand()%nv;
        while(occurence_int(rdm,nonocc,i)){
            rdm=rand()%nv;
        }
        cptab[i]=kptab[rdm];
        nonocc[i]=rdm;
        str=key_to_str(cptab[i]);
        fprintf(candidates,"%s\n",str);
        free(str);
    }
    // Ecriture du fichier declarations.txt
    for(int i=0;i<nv;i++){
        srand(time(NULL)*rand());
        int r=rand()%nc;
        char *kpstr=key_to_str(kptab[i]);
        mess=key_to_str(cptab[r]); 
        sgn=sign(mess,kstab[i]);
        str=signature_to_str(sgn);
        fprintf(declarations,"%s %s %s\n",kpstr,mess,str);
        free(str);
        free(mess);
        free(kpstr);
        free_signature(sgn);
    }
    // Libération des clés
    for(int i=0;i<nv;i++){
        free(kstab[i]);
        free(kptab[i]);
    }
    fclose(keys);
    fclose(candidates);
    fclose(declarations);
}