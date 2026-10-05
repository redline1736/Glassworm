CC      ?= gcc
# Removed -Werror, added warning suppressions
CFLAGS  += -Wall -Wextra -O2 -D_GNU_SOURCE -pthread \
           -Wno-unused-result -Wno-unused-function \
           -Wno-format-truncation -Wno-sign-compare
LIBS    := -lcurl -lpthread -lcjson

SRCS = src/main.c \
       src/graphql/gq.c \
       src/http/http.c \
       src/sock/sock.c \
       src/util/util.c

HDRS := $(wildcard src/*.h src/*/*.h)
BIN  := Glassworm

.PHONY: all clean sanitize

all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -I. $(SRCS) -o $@ $(LIBS)

# build with Address/UB sanitizers for local dev
sanitize: CFLAGS += -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: LIBS += -fsanitize=address,undefined
sanitize: $(BIN)

clean:
	rm -f $(BIN)