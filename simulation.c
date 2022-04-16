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
#include "blockchain.h"
#include "simulation.h"

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
