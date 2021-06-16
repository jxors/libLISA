all: minimal-executable

minimal-executable.o: minimal-executable.s
	nasm -f elf64 minimal-executable.s

minimal-executable: minimal-executable.o
	ld minimal-executable.o -o minimal-executable
