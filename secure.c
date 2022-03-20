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

/* Fonction de création de clés publiques/privées
-- pKey et sKey doivent être instanciés en amont */
void init_pair_keys(Key *pKey,Key *sKey,long low_size,long up_size){
    long n=0,s=0,u=0;
    generate_key_values(random_prime_number(low_size,up_size,5000),random_prime_number(low_size,up_size,5000),&n,&s,&u);
    init_key(pKey,s,n);
    init_key(sKey,u,n);
}

/*Fonction de conversion d'une clé en chaine de caractères*/
char *key_to_str(Key *key){
    char *res=(char *)malloc(sizeof(char)*256);
    sprintf(res,"(%lx,%lx)",key->val,key->n);
    return res;
}

/*Fonction de conversion d'une chaine de caractères en clé*/
Key *str_to_key(char *str){
    Key *key=(Key *)malloc(sizeof(Key));
    sscanf(str,"(%lx,%lx)",&(key->val),&(key->n));
    return key;
}

/*Fonction d'initialisation d'une signature*/
Signature* init_signature(long* content, int size){
    Signature *res=(Signature *)malloc(sizeof(Signature));
    res->tab=content;
    res->n=size;
    return res;
}
/*Fonction de libération d'une signature*/
void free_signature(Signature *sgn){
    free(sgn->tab);
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
    result[0]= '#';
    int pos = 1;
    char buffer[156];
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
/*Fonction d'initialisation d'une structure Protected (Déclaration signée)*/
Protected* init_protected(Key* pKey, char* mess, Signature* sgn){
    Protected *res=(Protected *)malloc(sizeof(Protected));
    res->pKey=pKey;
    res->mess=mess;
    res->sgn=sgn;
    return res;
}

void free_protected(Protected *p){
    free(p->pKey);
    free(p->mess);
    free_signature(p->sgn);
    free(p);
}

/*Fonction de vérification du message crypté avec la clé publique*/
int verify(Protected *pr){
    char *t=decrypt(pr->sgn->tab,pr->sgn->n,pr->pKey->val,pr->pKey->n);
    char dc[200];
    strcpy(dc,t);
    free(t);
    return strcmp(pr->mess,dc);
}

/*Fonction de conversion d'une structure Protected en chaine de caractères*/
char *protected_to_str(Protected *pr){
    char *res=malloc(sizeof(char)*256);
    char *k=key_to_str(pr->pKey);
    char *s=signature_to_str(pr->sgn);
    sprintf(res,"%s %s %s",k,pr->mess,s);
    free(k);
    free(s);
    free(pr);
    return res;
}

/*Fonction de conversion d'une chaine de caractères en structure Protected (Déclaration signée)*/
Protected *str_to_protected(char *str){
    char k[200];
    char *m=malloc(sizeof(char)*200);
    char s[200];
    sscanf(str,"%s %s %s",k,m,s);
    Protected *p=init_protected(str_to_key(k),m,str_to_signature(s));
    free(str);
    return p;
}

/*Fonction de création de données d'élections
-- Les données sont stockés dans les fichiers keys.txt,candidates.txt et declarations.txt*/
void generate_random_data(int nv,int nc){
    FILE *keys=fopen("keys.txt","w");
    FILE *candidates=fopen("candidates.txt","w");
    FILE *declarations=fopen("declarations.txt","w");
    Key *kptab[nv];
    Key *kstab[nv];
    Key *ctab[nc];
    char *mess;
    Signature *sgn;
    
    for(int i=0;i<nv;i++){
        srand(time(NULL)*rand());
        kptab[i]=malloc(sizeof(Key));
        kstab[i]=malloc(sizeof(Key));
        init_pair_keys(kptab[i],kstab[i],3,7);
        fprintf(keys,"%s %s\n",key_to_str(kptab[i]),key_to_str(kstab[i]));
    }
    
    for(int i=0;i<nc;i++){
        srand(time(NULL)*rand());
        ctab[i]=kptab[rand()%nv];
        fprintf(candidates,"%s\n",key_to_str(ctab[i]));
    }
    
    for(int i=0;i<nv;i++){
        srand(time(NULL)*rand());
        mess=key_to_str(ctab[rand()%nc]);
        sgn=sign(mess,kptab[i]);
        fprintf(declarations,"%s\n",signature_to_str(sgn));
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