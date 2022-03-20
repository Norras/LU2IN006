
#include <time.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include "protocol.h"

/*Fonction naive de test si p est premier ou non
    -- Complexité en O(p) (Possibilité de l'améliorer en oubliant le test sur les nombres pairs)*/
int is_prime_naive(long p){
    if (p%2==0) return 0;
    for(int i=3;i<p-1;i++){
        if (p%i==0) return 0;
    }
    return 1;
}

/*Fonction de calcul de a à la puissance m modulo n*/
long modpow_naive(long a,long m,long n){
    long res=1;
    for(int i=0;i<m;i++){
        res=(res*a)%n;
    }
    return res;
}

/*Fonction de calcul de a à la puissance m modulo n*/
long modpow(long a,long m,long n){
    if (m<=1){
        return a%n;
    }
    long res=modpow(a,m/2,n);
    if (m%2==0){
        return (res*res)%n;
    } else {
        return (res*res*a)%n;
    }
}

int witness ( long a , long b , long d , long p ) {
    long x = modpow (a ,d , p ) ;
    if( x == 1) {
        return 0;
    }
    for( long i = 0; i < b ; i ++) {
        if( x == p -1) {
            return 0;
        }
    x = modpow (x ,2 , p ) ;
    }
    return 1;
}

long rand_long ( long low , long up ) {
    return rand () % ( up - low +1) + low ;
}

int is_prime_miller (long p,int k ) {
    if (p==2) {
        return 1;
    }
    if (!(p&1) || p<=1) { //on verifie que p est impair et different de 1
        return 0;
    }
    //on determine b et d :
    long b = 0;
    long d = p-1;
    while (!(d&1)) { //tant que d n’est pas impair
        d = d /2;
        b = b +1;
    }
    // On genere k valeurs pour a, et on teste si c’est un temoin :
    long a;
    int i;
    for(i=0;i<k;i++) {
        a=rand_long(2,p-1);
        if(witness(a,b,d,p)) {
            return 0;
        }
    }
    return 1;
}

long random_prime_number(int low_size,int up_size,int k){
    long res;
    for(int i=0;i<10000;i++){
        res=rand_long(pow(2,low_size-1),pow(2,up_size)-1);
        if (is_prime_miller(res,k)){
            return res;
        }
    }
    return -1;
}

/*int main(){
    srand(time(NULL));
    clock_t b1,e1;
    long res1,res2;
    clock_t b=clock();
    is_prime_naive(269851051);
    clock_t e=clock();
    printf("%.5ld ms\n\n",(e-b)*1000/CLOCKS_PER_SEC);

    FILE *f=fopen("valeurs.txt","w");
    for(unsigned long long int i=1;i<1000000000000000000;i=i*10){
        b=clock();
        res1=modpow_naive(i,100000,7);
        e=clock();
        b1=clock();
        res2=modpow(i,100000,7);
        e1=clock();
        printf("%lld %ld %ld\n",i,res1,res2);
        fprintf(f,"%lld %ld %ld\n",i,(e-b)*1000000/CLOCKS_PER_SEC,(e1-b1)*1000000/CLOCKS_PER_SEC);
    }
    fclose(f);
    printf("\n");
    long n,s,u,t;
    char *ph="Message a chiffrer.";
    long p=random_prime_number(0,3000,50);
    long q=random_prime_number(0,3000,50);
    generate_key_values(p,q,&n,&s,&u);
    long *tab=encrypt(ph,s,n);
    t=(p-1)*(q-1);
    printf("p : %ld \nq : %ld \nn : %ld \ns : %ld \nu : %ld \nt : %ld\n",p,q,n,s,u,t);
    for(int i=0;i<strlen(ph);i++){
        printf("%ld ",tab[i]);
    }
    printf("\n");
    char *dec=decrypt(tab,strlen(ph),u,n);
    printf("%s\n",dec);
    return 0;
}*/