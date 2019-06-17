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

CFLAGS += -Iyajl/build/yajl-2.1.1/include -Itrezor-crypto
LIB-YAJL := yajl/build/yajl-2.1.1/lib/libyajl_s.a
LIB-TREZOR := trezor-crypto/libtrezor-crypto.so
RPATH :=  -Wl,-rpath=$(dir $(LIB-TREZOR))

SRCS	:= $(shell find -maxdepth 1 -name "UID_*.c")
SRCS  += base64.c
LIBS	+= -L $(dir $(LIB-YAJL)) -l $(patsubst lib%,%, $(basename $(notdir $(LIB-YAJL))))
LIBS	+= -L $(dir $(LIB-TREZOR)) -l $(patsubst lib%,%, $(basename $(notdir $(LIB-TREZOR))))

OBJS   = $(SRCS:.c=.o)

HEADERS   := $(shell find -maxdepth 1 -name "UID_*.h")

MBED_TLS_BASE := ../mbedTLS
TLS_LIB_DIR := $(MBED_TLS_BASE)/library
TLS_LIBS := $(TLS_LIB_DIR)/libmbedx509.a $(TLS_LIB_DIR)/libmbedtls.a $(TLS_LIB_DIR)/libmbedcrypto.a

#CFLAGS +=
#CFLAGS += -D MG_ENABLE_FILESYSTEM=0 -D MG_ENABLE_SSL=1 -D MG_SSL_MBED_DUMMY_RANDOM=1 -I../mongoose -Wno-redundant-decls -Wno-format-nonliteral -Wno-strict-prototypes
#CFLAGS += -D MG_ENABLE_FILESYSTEM=0 -D MG_ENABLE_SSL=1 -D MG_SSL_MBED_DUMMY_RANDOM=1 -I../mongoose -D MG_SSL_IF=MG_SSL_IF_MBEDTLS -I$(MBED_TLS_BASE)/include -Wno-redundant-decls -Wno-format-nonliteral -Wno-strict-prototypes
CFLAGS += -I$(MBED_TLS_BASE)/include

all: libuidcore-c.so

yajl/build/Makefile:
	mkdir yajl/build
	cd yajl/build; cmake ..

$(LIB-YAJL): yajl/build/Makefile
	make -C yajl/build

$(LIB-TREZOR):
	make -C trezor-crypto $(notdir $(LIB-TREZOR))

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<


libuidcore-c.so: $(SRCS) $(HEADERS) Makefile $(LIB-YAJL) $(LIB-TREZOR)
	$(CC) $(CFLAGS) -fPIC -shared $(SRCS) -Wl,-rpath='$$ORIGIN' $(LIBS) -o libuidcore-c.so

$(TLS_LIB_DIR)/libmbedx509.a:
	make -C $(MBED_TLS_BASE) lib

$(TLS_LIB_DIR)/libmbedtls.a:
	make -C $(MBED_TLS_BASE) lib

$(TLS_LIB_DIR)/libmbedcrypto.a:
	make -C $(MBED_TLS_BASE) lib

tests: tests.c $(SRCS) $(HEADERS) Makefile $(LIB-YAJL) $(LIB-TREZOR) $(TLS_LIBS)
	$(CC) $(CFLAGS) tests.c $(SRCS) $(LIBS) $(RPATH) $(TLS_LIBS) -lcunit -ftest-coverage -fprofile-arcs -o tests

run-tests: tests
	./tests
	gcov $(SRCS) -r

.PHONY: docs
docs:
	rm -rf docs
	$(CC) $(CFLAGS) -fsyntax-only example_init.c example_provider.c example_user.c
	doxygen Doxyfile

clean:
	rm -f *.o tests libuidcore-c.so
	rm -rf yajl/build
	make -C trezor-crypto clean
	rm -rf docs
	rm -f *.gcda *.gcno *.gcov
	if [ -f '$(MBED_TLS_BASE)/Makefile' ]; then make -C $(MBED_TLS_BASE) clean; fi

.PHONY: clean_repo
clean_repo:
	rm -rf $(MBED_TLS_BASE)

.PHONY: clone_repo
clone_repo:
	git clone --recurse-submodules https://github.com/ARMmbed/mbedtls.git $(MBED_TLS_BASE) -b mbedtls-2.16.1
