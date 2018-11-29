all : tcp_block

tcp_block: main.o
	g++ -g -o tcp_block main.o -lpcap

main.o:
	g++ -g -c -o main.o tcp_block.cpp

clean:
	rm -f tcp_block
	rm -f *.o

