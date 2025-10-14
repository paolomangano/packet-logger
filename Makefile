# Makefile for packet-tracer

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = -lpcap

# Directories
SRCDIR = src
OBJDIR = obj

# Target executable
TARGET = packet-tracer

# Source files
SOURCES = $(SRCDIR)/packet-tracer.c
OBJECTS = $(OBJDIR)/packet-tracer.o

# Default target
all: $(TARGET)

# Create object directory if it doesn't exist
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Compile source files to object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files to create executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Install target (optional)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

# Uninstall target (optional)
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

# Test build (compile without running)
test-build: $(TARGET)
	@echo "Build successful: $(TARGET)"

# Help target
help:
	@echo "Available targets:"
	@echo "  all        - Build the packet-tracer executable (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install packet-tracer to /usr/local/bin/"
	@echo "  uninstall  - Remove packet-tracer from /usr/local/bin/"
	@echo "  test-build - Test compilation without running"
	@echo "  help       - Show this help message"

# Declare phony targets
.PHONY: all clean install uninstall test-build help