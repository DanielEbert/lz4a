# LZ4 source files
LZ4_SRCDIR = lz4/src
LZ4_INCDIR = lz4/inc
LZ4_SOURCES = $(LZ4_SRCDIR)/lz4.c $(LZ4_SRCDIR)/lz4hc.c $(LZ4_SRCDIR)/lz4frame.c $(LZ4_SRCDIR)/xxhash.c

# Build variables
CXX = g++
CXXFLAGS = -std=c++17 -O3
CC = gcc
CFLAGS = -O3

# Object files
LZ4_OBJECTS = $(LZ4_SOURCES:.c=.o)

all: lz4a

# Build LZ4 object files
$(LZ4_SRCDIR)/%.o: $(LZ4_SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(LZ4_INCDIR) -c $< -o $@

# Build main executable
lz4a: $(LZ4_OBJECTS) lz4d.cpp
	$(CXX) $(CXXFLAGS) -I$(LZ4_INCDIR) lz4d.cpp $(LZ4_OBJECTS) -o lz4a

clean:
	rm -f $(LZ4_OBJECTS) lz4a

.PHONY: all clean
