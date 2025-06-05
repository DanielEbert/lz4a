all:
	g++ -std=c++17 lz4d.cpp -o lz4a -I/opt/homebrew/include -L/opt/homebrew/lib -llz4

test:
	./test.sh
