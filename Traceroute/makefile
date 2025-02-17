# compiler and flags, Wall: enable all warnings
CC = gcc
CFLAGS = -Wall

# executable name
TARGET = prog

# Source files
SRCS = main.c utils.c

# Object files (source -> .o)
OBJS = $(SRCS:.c=.o)

# Default target to build the program
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# clean up
clean:
	rm -f $(OBJS) $(TARGET)