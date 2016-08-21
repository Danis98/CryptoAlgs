LIB_NAME=libcrypto.a
OBJS=		\
block/block.o	\
block/feistel.o	\
modes/cbc.o	\
bitperm.o	\
util.o

INCLUDE_DIR=./include
CPP_FLAGS=-std=c++11

all: $(OBJS)
	ar rcs $(LIB_NAME) $(OBJS)

%.o: %.cpp
	g++ -c $< -o $@ -I$(INCLUDE_DIR) $(CPP_FLAGS)

clean:
	rm -rf $(OBJS) $(LIB_NAME)
