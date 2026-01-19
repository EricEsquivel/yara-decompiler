
CC = gcc
CFLAGS = -I./yara/libyara/include -I..
LDFLAGS = -lm

yara-decompiler: parser.o disassembler.o decompiler.o pretty_printer.o
	$(CC) -o yara-decompiler parser.o disassembler.o decompiler.o pretty_printer.o $(LDFLAGS)

parser.o: parser.c decompiler.h
	$(CC) $(CFLAGS) -c parser.c

disassembler.o: disassembler.c disassembler.h
	$(CC) $(CFLAGS) -c disassembler.c

decompiler.o: decompiler.c decompiler.h
	$(CC) $(CFLAGS) -c decompiler.c

pretty_printer.o: pretty_printer.c decompiler.h
	$(CC) $(CFLAGS) -c pretty_printer.c

clean:
	rm -f yara-decompiler parser.o disassembler.o decompiler.o pretty_printer.o
