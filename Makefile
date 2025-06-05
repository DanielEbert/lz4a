all:
ifeq ($(shell uname), Linux)
	# Ubuntu build
	g++ -std=c++17 lz4d.cpp -o lz4a -llz4 -O3
else
	# macOS or others
	g++ -std=c++17 lz4d.cpp -o lz4a -I/opt/homebrew/include -L/opt/homebrew/lib -llz4
endif

debug:
	g++ -std=c++17 lz4d.cpp -o lz4a -llz4 -fsanitize=address -g -Og

test:
	./test.sh
