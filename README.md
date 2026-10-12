# LU2IN006 — Mini-projet de vote sécurisé et blockchain (C)

Ce projet fait partie d'un travail lié à l'UE "Structures de données" de Sorbonne Université.

Il implémente, en C, un système de vote électronique simplifié :
- génération de paires de clés (type RSA simplifié),
- signatures de déclarations de vote,
- validation des votes,
- calcul du gagnant,
- enregistrement des votes dans une blockchain locale.

L’objectif est pédagogique : manipuler des structures de données, de la crypto de base, et une logique de chaîne de blocs.

## Structure du projet

### Modules principaux
- `prime.c/.h` : primalité, exponentiation modulaire, génération de nombres premiers.
- `protocol.c/.h` : chiffrement/déchiffrement et génération de clés.
- `secure.c/.h` : structures `Key`, `Signature`, `Protected` + sérialisation/signature/vérification.
- `list_data.c/.h` : listes chaînées de clés et de votes, lecture/écriture fichiers, filtrage des signatures invalides.
- `winner.c/.h` : table de hachage et calcul du gagnant.
- `blockchain.c/.h` : blocs, preuve de travail, arbre de blocs, gagnant sur la plus longue chaîne.

### Programmes de test / démonstration
- `main` : test chiffrement/déchiffrement.
- `main2` : test signatures et génération de données.
- `mainlist_data` : test des lectures de listes et du filtrage des votes valides.
- `mainwinner` : test du calcul du gagnant sans blockchain.
- `mainbc` : tests blockchain intermédiaires.
- `fmain` : scénario global (beaucoup de votes, création de blocs, calcul du gagnant final).

### Données
- `keys.txt`, `candidates.txt`, `declarations.txt` : générés automatiquement.
- dossier `Blockchain/` : blocs (`Block*.txt` / `block*.txt`) et fichiers temporaires (`Pending_*`).

## Compilation

Prérequis :
- `gcc`
- `make`
- OpenSSL (`libssl` / `libcrypto`) pour SHA-256

Compiler toutes les cibles :

```bash
make
```

Nettoyer les binaires et fichiers générés :

```bash
make clear
```

## Exécution

Après compilation :

```bash
./main
./main2
./mainlist_data
./mainwinner
./mainbc
./fmain
```

## Déroulé logique (vue simple)

1. On génère des électeurs et des candidats.
2. Chaque électeur signe une déclaration de vote.
3. On filtre les déclarations à signature invalide.
4. On compte les voix valides pour déterminer un gagnant.
5. Version blockchain : les votes sont ajoutés dans des blocs, puis validés par preuve de travail.
6. Le gagnant final est calculé à partir de la plus longue chaîne.

## Remarques

- Le projet est orienté apprentissage, pas production.
- Certaines cibles `main*` sont des bancs d’essai (debug/expérimentation).
- La cohérence de certains noms de fichiers dans `Blockchain/` (`Block` vs `block`) dépend des exécutions passées.
