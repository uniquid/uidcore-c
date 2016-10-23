#CC        = gcc

#OPTFLAGS  = -O3 -g
OPTFLAGS = -O0 -g -gdwarf-3

CFLAGS   += $(OPTFLAGS) \
            -std=gnu99 \
            -W \
            -Wall \
            -Wextra \
            -Wimplicit-function-declaration \
            -Wredundant-decls \
            -Wstrict-prototypes \
            -Wundef \
            -Wshadow \
            -Wpointer-arith \
            -Wformat \
            -Wreturn-type \
            -Wsign-compare \
            -Wmultichar \
            -Wformat-nonliteral \
            -Winit-self \
            -Wuninitialized \
            -Wformat-security \
            -Werror

CFLAGS += -I../yajl/build/yajl-2.1.1/include -I../trezor-crypto


SRCS	:= $(shell find  -name "*.c")
SRCS  += 
LIBS	+= -L../yajl/build/yajl-2.1.1/lib/ -lyajl_s 

OBJS   = $(SRCS:.c=.o)

HEADERS   := $(shell find  -name "*.h")

all: libuidcore-c.so


%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<


libuidcore-c.so: $(SRCS) $(HEADERS) Makefile
	$(CC) $(CFLAGS) -fPIC -shared $(SRCS) $(LIBS) -o libuidcore-c.so


clean:
	rm -f *.o tests libuidcore-c.so
