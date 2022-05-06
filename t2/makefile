# All Targets
all: task2b

task2b: task2b.o
	gcc -g -Wall -m32 -o task2b task2b.o

# Dependancies:
task2b.o: task2b.c
	gcc -g -Wall -m32 -c -o task2b.o task2b.c

.PHONY: clean

# Clean the build directory
clean:
	rm -f *.o task2b


