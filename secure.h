#ifndef SECURE_H
#define SECURE_H

typedef struct Key{
    long val,n;
}Key;

typedef struct Signature{
    long *tab;
    int n;
}Signature;

typedef struct Protected{
    Key *pKey;
    char *mess;
    Signature *sgn;
}Protected;

void init_key(Key* key, long val, long n);
void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size);
char *key_to_str(Key* key);
Key *str_to_key(char* str);

Signature* init_signature(long* content, int size);
void free_signature(Signature* sgn);
Signature* sign(char* mess, Key* sKey);
Signature *str_to_signature(char *str);
char *signature_to_str(Signature *sgn);

Protected* init_protected(Key* pKey, char* mess, Signature* sgn);
int verify(Protected *pr);
void free_protected(Protected *p);
char *protected_to_str(Protected *pr);
Protected *str_to_protected(char *str);

void generate_random_data(int nv,int nc);
#endif