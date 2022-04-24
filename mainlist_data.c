#include "list_data.h"
#include "protocol.h"
#include "prime.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main(){
    generate_random_data(15,5);
    CellKey *list=read_public_keys("keys.txt");
    CellProtected *plist=read_protected("declarations.txt");

    plist=valid_list_protected(plist);
    print_list_protected(plist);
    delete_list_protected(plist);
    
    print_list_keys(list);
    delete_list_keys(list);
}