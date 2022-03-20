all: main main2


main: main.c prime.c protocol.c
	gcc -Wall -o main main.c prime.c protocol.c -lm

main2: main2.c prime.c protocol.c secure.c
	gcc -Wall -o main2 main2.c prime.c protocol.c secure.c -lm


clear:
	rm -rf main
	rm -rf main2
	rm -rf candidates.txt
	rm -rf declarations.txt
	rm -rf keys.txt