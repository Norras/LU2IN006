#ifndef _H_LIST_DATA_
#define _H_LIST_DATA_

#include "secure.h"

typedef struct cellKey{
    Key *data;
    struct cellKey *next;
}CellKey;

typedef struct cellProtected{
    Protected *data;
    struct cellProtected *next;
}CellProtected;

CellKey *create_cell_key(Key *key);
CellKey *add_head_cellkey(CellKey *list,Key *key);
CellProtected *create_cell_protected(Protected *pr);
CellProtected *add_head_cellprotected(CellProtected *list,Protected *cpr);
void add_tail_cellprotected(CellProtected **list,Protected *cpr);
void delete_list_protected(CellProtected *list);
void delete_cell_protected(CellProtected *c);
CellProtected *read_protected(char *filename);
CellKey *read_public_keys(char *fichier);
void delete_list_keys(CellKey *list);
void delete_cell_key(CellKey *c);
void print_list_protected(CellProtected *LCP);
void print_list_keys(CellKey *LCK);
CellProtected *valid_list_protected(CellProtected *list);
char *CPlist_to_str(CellProtected *list);
void fusion_cell_protected(CellProtected **first, CellProtected *second);


#endif