PROJECTS=DES lucifer
LIB_CRYPTO_DIR=./crypto
CPP_FLAGS=-std=c++11
CRYPTO_LIB_INCLUDES=$(LIB_CRYPTO_DIR)/include

.PHONY: clean libcrypto

all: libcrypto $(PROJECTS)

%:%.cpp libcrypto
	g++ -static $< -o $@ -L$(LIB_CRYPTO_DIR) -lcrypto $(CPP_FLAGS) -I$(CRYPTO_LIB_INCLUDES)

clean:
	rm -rf *.o *.save $(PROJECTS)
	$(MAKE) -C $(LIB_CRYPTO_DIR) clean

libcrypto:
	$(MAKE) -C $(LIB_CRYPTO_DIR)

.PHONY: libcrypto
