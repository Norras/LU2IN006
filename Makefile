all: main main2 winner


main: main.c prime.c protocol.c
	gcc -Wall -o main main.c prime.c protocol.c -lm -g

main2: main2.c prime.c protocol.c secure.c
	gcc -Wall -o main2 main2.c prime.c protocol.c secure.c -lm -g

list_data: list_data.c prime.c protocol.c secure.c
	gcc -Wall -o list_data list_data.c prime.c protocol.c secure.c -lm -g

# winner: winner.c list_data.c prime.c protocol.c secure.c
# 	gcc -Wall -o winner winner.c list_data.c prime.c protocol.c secure.c -lm -g
clear:
	rm -rf main
	rm -rf main2
	rm -rf candidates.txt
	rm -rf declarations.txt
	rm -rf keys.txt
	rm -rf list_data
	rm -rf winner