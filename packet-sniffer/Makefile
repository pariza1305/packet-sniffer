# Makefile for C-Shark Packet Sniffer

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
LDFLAGS = -lpcap
TARGET = cshark

# Source files and object files
SRCDIR = src
INCDIR = include
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Link object files to create the executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "C-Shark compiled successfully. Run with 'sudo ./cshark'"

# Compile source files into object files
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJECTS) $(TARGET)
	@echo "Cleaned up build files."

# Phony targets
.PHONY: all clean