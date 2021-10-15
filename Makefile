.PHONY: all
all: requirements hashlib

requirements:
	pip3 install -r requirements.txt

hashlib: 
	make -C src/hash_lib all

.PHONY: clean
clean: 
	make -C src/hash_lib clean