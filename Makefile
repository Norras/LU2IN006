all: main main2 mainbc fmain


main: main.c prime.c protocol.c
	gcc -Wall -o main main.c prime.c protocol.c -lm -g

main2: main2.c prime.c protocol.c secure.c
	gcc -Wall -o main2 main2.c prime.c protocol.c secure.c -lm -g

# list_data: list_data.c prime.c protocol.c secure.c
# 	gcc -Wall -o list_data list_data.c prime.c protocol.c secure.c -lm -g

mainbc: mainbc.c blockchain.c list_data.c prime.c protocol.c secure.c winner.c
	gcc -Wall -o mainbc mainbc.c blockchain.c list_data.c prime.c protocol.c secure.c winner.c -lm -lssl -lcrypto -g

# winner: winner.c list_data.c prime.c protocol.c secure.c
# 	gcc -Wall -o winner winner.c list_data.c prime.c protocol.c secure.c -lm -g

fmain: fmain.c blockchain.c list_data.c prime.c protocol.c secure.c winner.c
	gcc -Wall -o $@ $^ -lm -lssl -lcrypto -g
clear:
	rm -rf *.exe
	rm -rf main
	rm -rf mainbc
	rm -rf main2
	rm -rf candidates.txt
	rm -rf declarations.txt
	rm -rf keys.txt
	rm -rf list_data
	rm -rf winner