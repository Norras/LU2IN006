#ifndef __WINNER_H__
#define __WINNER_H__
#include "secure.h"
typedef struct hashcell{
    Key *key;
    int val;
}HashCell;

typedef struct hashtable{
    HashCell* *tab;
    int size;
}HashTable;

int find_position(HashTable *t,Key *key);
int hash_function(Key *key,int size);
HashCell *create_hashcell(Key *key);
void delete_hashtable(HashTable *t);
#endif

