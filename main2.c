#include "protocol.h"
#include "prime.h"
#include "secure.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void print_long_vector(long *result,int size){
    printf("Vector: [");
    for(int i=0;i<size;i++){
        printf("%lx \t",result[i]);
    }
    printf("]\n");
}

int main(void){
    srand(time(NULL));

    //Testing Init Keys

    Key *pKey=malloc(sizeof(Key));
    Key *sKey=malloc(sizeof(Key));
    init_pair_keys(pKey,sKey,3,7);
    printf("pKey: %lx, %lx \n",pKey->val,pKey->n);
    printf("sKey: %lx, %lx \n",sKey->val,sKey->n);

    //Testing Key Serialization
    char *chaine=key_to_str(pKey);
    printf("key_to_str: %s \n",chaine);
    Key *k=str_to_key(chaine);
    printf("str_to_key: %lx, %lx \n",k->val,k->n);

    //Testing signature
    //Candidate keys:
    Key *pKeyC=malloc(sizeof(Key));
    Key *sKeyC=malloc(sizeof(Key));
    init_pair_keys(pKeyC,sKey,3,7);
    
    //Declaration:
    char *mess=key_to_str(pKeyC);
    char *vote=key_to_str(pKey);
    printf("%s vote pour %s\n",vote,mess);
    free(vote);
    Signature *sgn=sign(mess,sKey);
    printf("signature: ");
    print_long_vector(sgn->tab,sgn->n);
    free(chaine);
    chaine=signature_to_str(sgn);
    printf("signature_to_str: %s \n",chaine);
    free_signature(sgn);
    sgn=str_to_signature(chaine);
    free(chaine);
    printf("str_to_signature: ");
    print_long_vector(sgn->tab,sgn->n);

    //Testing protected:
    Protected *pr=init_protected(pKey,mess,sgn);

    //Verification:
    if(verify(pr)){
        printf("Signature valide\n");
    } else {
        printf("Signature non valide\n");
    }
    
    chaine=protected_to_str(pr);
    free(pr);
    printf("protected_to_str: %s\n",chaine);
    pr=str_to_protected(chaine);
    
    char *st=key_to_str(pr->pKey);
    char *sgnstr=signature_to_str(pr->sgn);
    printf("str_to_protected: %s %s %s\n",st,pr->mess,sgnstr);

    generate_random_data(50,20);
    
    free(chaine);
    free(sgn->tab);
    free(sgn);
    free(st);
    free(sgnstr);
    free(mess);
    free_protected(pr);
    free(pKey);
    free(k);
    free(sKey);
    free(pKeyC);
    free(sKeyC);
    return 0;
}