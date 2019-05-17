SRCE = 10.0.2.19 # fake address
DEST = 10.0.2.5 # the nameserver

11:11.c
	@gcc 11.c -o 11.o
	@./11.o

12:12.c header.h
	@gcc 12.c -o 12.o -lpcap
	@sudo ./12.o ${SRCE} ${DEST}
