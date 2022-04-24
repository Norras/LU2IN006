all: main main2 mainbc fmain mainwinner mainlist_data


main: main.c prime.c protocol.c
	gcc -Wall -o main main.c prime.c protocol.c -lm -g

main2: main2.c prime.c protocol.c secure.c
	gcc -Wall -o main2 main2.c prime.c protocol.c secure.c -lm -g

mainlist_data: mainlist_data.c list_data.c prime.c protocol.c secure.c
	gcc -Wall -o mainlist_data mainlist_data.c list_data.c prime.c protocol.c secure.c -lm -g

mainbc: mainbc.c blockchain.c list_data.c prime.c protocol.c secure.c winner.c
	gcc -Wall -o mainbc mainbc.c blockchain.c list_data.c prime.c protocol.c secure.c winner.c -lm -lssl -lcrypto -g

mainwinner: mainwinner.c winner.c list_data.c prime.c protocol.c secure.c
	gcc -Wall -o mainwinner mainwinner.c winner.c list_data.c prime.c protocol.c secure.c -lm -g

fmain: fmain.c blockchain.c list_data.c prime.c protocol.c secure.c winner.c
	gcc -Wall -o $@ $^ -lm -lssl -lcrypto -g


clear:
	rm -rf *.exe
	rm -rf main
	rm -rf main2
	rm -rf mainbc
	rm -rf candidates.txt
	rm -rf declarations.txt
	rm -rf keys.txt
	rm -rf mainlist_data
	rm -rf mainwinner
	rm -rf fmain