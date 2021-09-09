/**
 * @file acs.h
 * @author Fanourakis Nikos
 * @brief 
 * 
 */

#include "queue/queue.h"

#define MAX_LINE_SIZE 1024
#define TOTAL_SYSCALLS 341

typedef struct system_call
{
    int syscall_num;
    char *syscall_name;
} system_call;

typedef struct restricted_syscall
{
    system_call syscall;
    unsigned int max_calls; /* The maximum amount of times this syscall can be called in a second */
    queue_t *calls_per_sec; /* Keeps the calls of this systemcall in the current period (in a second when we check for violation) */
    struct restricted_syscall *next;
} restricted_syscall;

typedef struct restricted_syscalls_list
{
    int size;
    restricted_syscall *head;
} restricted_syscalls_list;

typedef struct syscall_sequence
{
    system_call syscall;
    struct syscall_sequence *next;
} syscall_sequence;

typedef struct syscalls_sequence_list
{
    int size;
    syscall_sequence *head;
} syscalls_sequence_list;

/**
 * @brief   Reads the instruction file and stores its information
 *          in the sequence and restricted syscalls lists.
 * 
 * @param filename  Name of instruction file
 * @param list      Restricted syscalls list
 * @param seq       Sequence syscalls list
 * @return int      0 on failure, 1 on success
 */
int read_instructions_file(char *filename, restricted_syscalls_list *list, syscalls_sequence_list *seq);

/**
 * @brief   Checks if a restricted syscall is called more times in a second
 *          than the maximum allowed (max_calls).
 * 
 * @param res_syscall   Restricted syscall
 * @return int          Returns 1 if there is violation, else 0
 */
int checkViolation(restricted_syscall *res_syscall);

/**
 * @brief   Checks if sequence is detected.
 *          If it is then it returns 1, else 0.
 * 
 * @param seq               The sequence list
 * @param latest_syscalls   A queue which keeps the latest calls of syscalls (max size of the queue is the size of sequence syscalls list)
 * @return int              1 if sequence is detected, else 0.
 */
int enable_access_control(syscalls_sequence_list *seq, queue_t *latest_syscalls);

/**
 * @brief       Executes the executable program via a child process and traces this program from parent process
 *              using ptrace.
 * 
 * @param exec  Executable program
 * @param list  Restricted syscalls list
 * @param seq   Sequence syscalls list
 */
void execute_program(char **exec, restricted_syscalls_list *list, syscalls_sequence_list *seq);

/**
 * @brief   Matches the syscall name with the syscall number
 * 
 * @param syscall_name  Name of systemcall
 * @return int          Returns the systemcall number, or -1 on failure
 */
int get_syscall_num(char *syscall_name);

/***************   Restricted System calls List   ***************/

/**
 * @brief   Allocates memory for the restricted syscalls list
 * 
 * @return restricted_syscalls_list* Restricted syscalls list
 */
restricted_syscalls_list *init_restricted_syscalls_list();

/**
 * @brief   Inserts a syscall in the restricted syscalls list
 * 
 * @param list          Restricted syscalls list
 * @param syscall_name  Syscall name
 * @param syscall_num   Syscall number
 * @param max_calls     Max calls per second allowed for this syscall
 */
void insert_restricted_syscalls_list(restricted_syscalls_list *list, const char *syscall_name, int syscall_num, int max_calls);

/**
 * @brief   Searches if the systemcall with this number is restricted.
 * 
 * @param list                  Restricted syscalls list
 * @param syscall_num           Syscall number
 * @return restricted_syscall*   Returns the restricted syscall if found, else null.
 */
restricted_syscall *lookup_restricted_syscalls_list(restricted_syscalls_list *list, int syscall_num);

/**
 * @brief   Clears and deallocates the restricted syscalls list
 * 
 * @param list  Restricted syscalls list
 */
void destruct_restricted_syscalls_list(restricted_syscalls_list *list);

/**
 * @brief   Prints the restricted syscalls list
 * 
 * @param list  Restricted syscalls list
 */
void print_restricted_syscalls_list(restricted_syscalls_list *list);

/***************   System calls Sequence List   ***************/

/**
 * @brief   Allocates memory for the sequence syscalls list
 * 
 * @return syscalls_sequence_list* Sequence syscalls list
 */
syscalls_sequence_list *init_syscalls_sequence_list();

/**
 * @brief   Inserts a syscall in the sequence syscalls list
 * 
 * @param list          Sequence syscalls list
 * @param syscall_name  Syscall name
 * @param syscall_num   Syscall number
 */
void insert_syscalls_sequence_list(syscalls_sequence_list *list, const char *syscall_name, int syscall_num);

/**
 * @brief   Clears and deallocates the sequence syscalls list
 * 
 * @param list  Sequence syscalls list
 */
void destruct_syscalls_sequence_list(syscalls_sequence_list *list);

/**
 * @brief   Prints the sequence syscalls list
 * 
 * @param list  Sequence syscalls list
 */
void print_syscalls_sequence_list(syscalls_sequence_list *list);
