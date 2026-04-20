CC = gcc
CFLAGS = -O2 -Wall -Wextra -fno-strict-aliasing
LDFLAGS = -lcrypto

TARGET = lwe_auth
SRC = lwe_auth.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
