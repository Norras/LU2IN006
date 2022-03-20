#include "prime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* Fonction appliquant l'algorithme d'Euclide étendu 
-- Donne le PGCD de s et t en résultat
-- Donne les coefficients u et v correspondants*/
long extended_gcd(long s,long t,long *u,long *v){
    if (s==0){
        *u=0;
        *v=1;
        return t;
    }
    long uPrim,vPrim;
    long gcd=extended_gcd(t%s,s,&uPrim,&vPrim);
    *u=vPrim-(t/s)*uPrim;
    *v=uPrim;
    return gcd;
}


/* Génère des clés publiques/privées à partir de deux nombres premiers p et q
-- (s,n) est la clé publique et (u,n) est la clé privée*/
void generate_key_values(long p,long q,long *n,long *s,long *u){
    long v;
    long t=(p-1)*(q-1);
    *n=p*q;
    *s=rand_long(0,t);
    while (extended_gcd(*s,t,u,&v)!=1 || (*s**u)%t!=1){
        *s=rand_long(0,t);
    }
}

/* Fonction de cryptage d'une chaine de caractères chaine grâce à la clé publique (s,n)
-- PROBLEME : Donne un mauvais entier pour les caractères avec accents*/
long *encrypt(char *chaine,long s,long n){ 
    int i=0;
    int c;
    long *res=malloc(sizeof(long)*strlen(chaine));
    while (chaine[i]!='\0'){
        c=chaine[i];
        res[i]=modpow(c,s,n);
        i++;
    }
    return res;
}

/* Fonction de décryptage d'un tableau d'entier en une chaîne de caractère grâce à la clé privée (u,n)
-- Libère le tableau d'entier crypted de la mémoire*/
char *decrypt(long *crypted,int size,long u,long n){
    if (crypted==NULL){
        return NULL;
    }
    char *res=(char *)malloc(sizeof(char)*size+1);
    int i;
    for(i=0;i<size;i++){
        res[i]=(char)modpow(crypted[i],u,n);
    }
    res[i]='\0';
    return res;
}

