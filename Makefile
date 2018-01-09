CC=gcc
OPENSSLDIR=/usr/local/ssl
CFLAGS=-g -Wall -W -O2

RPATH=-R${OPENSSLDIR}/lib
LD=-L${OPENSSLDIR}/lib -lssl -lcrypto -lnsl -lpthread -ldl

COMMON_OBJ=obj/common.o
SERVER_OBJ=obj/server.o
CLIENT_OBJ=obj/client.o

$(COMMON_OBJ): src/common.c
	mkdir -p obj
	$(CC) $(CFLAGS) -c src/common.c -o $(COMMON_OBJ)

$(SERVER_OBJ): src/server.c
	$(CC) $(CFLAGS) -c src/server.c -o $(SERVER_OBJ)

$(CLIENT_OBJ): src/client.c
	$(CC) $(CFLAGS) -c src/client.c -o $(CLIENT_OBJ)

server: $(COMMON_OBJ) $(SERVER_OBJ)
	${CC} $(SERVER_OBJ) ${COMMON_OBJ} -o bin/server ${LD}

client: $(COMMON_OBJ) $(CLIENT_OBJ)
	${CC} $(CLIENT_OBJ) ${COMMON_OBJ} -o bin/client ${LD}

all: server client

clean:
	rm -f obj/*.o
