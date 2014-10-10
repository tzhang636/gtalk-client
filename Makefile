# CS 438 - Spring 2013 MP1

CC=/usr/bin/gcc
CC_OPTS=-g3
CC_LIBS=
CC_DEFINES=
CC_INCLUDES=
CC_FLAGS=-I include -L lib -lgnutls -lgsasl -lrecv_xml_nonblock
CC_ARGS=${CC_OPTS} ${CC_LIBS} ${CC_DEFINES} ${CC_INCLUDES} ${CC_FLAGS}

# clean is not a file
.PHONY=clean

# target "all" depends on all others
all: iGtalk

iGtalk: iGtalk.c
	@${CC} ${CC_ARGS} -o iGtalk iGtalk.c

clean:
	@rm -f iGtalk *.o
