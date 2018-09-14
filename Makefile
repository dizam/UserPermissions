TARGET = access
HEADERS = access.h
CFLAGS = -Wall

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	gcc $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	gcc $(OBJECTS) $(CFLAGS) -o $@

clean:
	-rm -f $(OBJECTS)
	-rm -f $(TARGET)
