# All Targets
all: task1c

task1c: task1c.o
	gcc -g -Wall -m32 -o task1c task1c.o

# Dependancies:
task1c.o: task1c.c
	gcc -g -Wall -m32 -c -o task1c.o task1c.c

.PHONY: clean

# Clean the build directory
clean:
	rm -f *.o task1c


