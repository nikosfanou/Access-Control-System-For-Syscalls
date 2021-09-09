# Fanourakis Nikos

CC = gcc
GCC_FLAGS = -pedantic -o

ACS_LIB = acs.h
QUEUE_LIB = queue/queue.h
ACS_IMP = acs.c
QUEUE_IMP = queue/queue.c
EXE_IMP = input_exec.c

EXEC_FILE = acs_exec
INPUT_EXEC = input_exec

all: $(ACS_IMP) $(ACS_LIB) $(EXE_IMP) $(QUEUE_LIB) $(QUEUE_IMP)
	$(CC) $(ACS_IMP) $(QUEUE_IMP) $(GCC_FLAGS) $(EXEC_FILE)
	$(CC) $(EXE_IMP) $(GCC_FLAGS) $(INPUT_EXEC)

clean:
	rm -f $(EXEC_FILE)
	rm -f $(INPUT_EXEC)
