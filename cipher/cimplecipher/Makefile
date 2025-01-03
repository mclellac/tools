# Variables
CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = cimplecipher

# Source files
SRCS = main.c ciphers.c utils.c
OBJS = $(SRCS:.c=.o)

# OS-specific settings
ifeq ($(OS),Windows_NT)
    EXE = .exe
    INSTALL_DIR = $(HOMEPATH)\\bin
    MKDIR = mkdir
    COPY = copy
    COLOR_RESET =
    COLOR_GREEN =
    COLOR_BLUE =
    COLOR_YELLOW =
    COLOR_RED =
else
    EXE =
    INSTALL_DIR = $(HOME)/bin
    MKDIR = mkdir -p
    COPY = cp
    COLOR_RESET = \033[0m
    COLOR_GREEN = \033[1;32m
    COLOR_BLUE = \033[1;34m
    COLOR_YELLOW = \033[1;33m
    COLOR_RED = \033[1;31m
endif

# Targets
all: $(TARGET)$(EXE)
	@printf "$(COLOR_GREEN)Build complete:$(COLOR_RESET) $(TARGET)$(EXE)\n"

$(TARGET)$(EXE): $(OBJS)
	@printf "$(COLOR_BLUE)Linking:$(COLOR_RESET) $@\n"
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	@printf "$(COLOR_YELLOW)Compiling:$(COLOR_RESET) $<\n"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@printf "$(COLOR_RED)Cleaning up...$(COLOR_RESET)\n"
	rm -f $(OBJS) $(TARGET)$(EXE)

install: $(TARGET)$(EXE)
	@printf "$(COLOR_BLUE)Installing $(TARGET)$(EXE) to $(INSTALL_DIR)...$(COLOR_RESET)\n"
	$(MKDIR) $(INSTALL_DIR)
	$(COPY) $(TARGET)$(EXE) $(INSTALL_DIR)
	@printf "$(COLOR_GREEN)Installation successful:$(COLOR_RESET) $(TARGET)$(EXE) is in $(INSTALL_DIR)\n"

.PHONY: all clean install
