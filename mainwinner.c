#include "list_data.h"
#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "winner.h"

int main(){
    generate_random_data(15,5);
    CellKey *voters=read_public_keys("keys.txt");
    CellKey *candidates=read_public_keys("candidates.txt");
    HashCell *cell=create_hashcell(voters->data);
    int sizeV=50;
    int sizeC=20;
    CellProtected *decl=valid_list_protected(read_protected("declarations.txt"));
    Key *winner=compute_winner(decl,candidates,voters,sizeC,sizeV);
    char *winnerstr=key_to_str(winner);
    printf("Winner : %s\n",winnerstr);

    // Libération des éléments créé
    delete_list_protected(decl);
    delete_list_keys(voters);
    delete_list_keys(candidates);
    free(cell);
    free(winner);
    free(winnerstr);
    return 0;
}