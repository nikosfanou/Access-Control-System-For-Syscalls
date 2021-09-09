/**
 * @file acs.c
 * @author Fanourakis Nikos
 * @brief Simple Access Control System Implementation
 * 
 */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
/*#include <unistd.h>*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "acs.h"

/***************   Restricted system calls List   ***************/
restricted_syscalls_list *init_restricted_syscalls_list()
{
    restricted_syscalls_list *list;

    list = (restricted_syscalls_list *)malloc(sizeof(restricted_syscalls_list));
    if (!list)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for restricted syscalls list.\n");
        exit(EXIT_FAILURE);
    }

    list->size = 0;
    list->head = NULL;

    return list;
}

/* Insert at the beginning */
void insert_restricted_syscalls_list(restricted_syscalls_list *list, const char *syscall_name, int syscall_num, int max_calls)
{
    restricted_syscall *newNode;

    assert(list && syscall_name);

    newNode = (restricted_syscall *)malloc(sizeof(restricted_syscall));
    if (!newNode)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for restricted syscall.\n");
        exit(EXIT_FAILURE);
    }

    newNode->syscall.syscall_name = strdup(syscall_name);
    newNode->syscall.syscall_num = syscall_num;
    newNode->max_calls = max_calls;
    newNode->calls_per_sec = queue_init();
    newNode->next = list->head;
    list->head = newNode;
    list->size++;
    return;
}

restricted_syscall *lookup_restricted_syscalls_list(restricted_syscalls_list *list, int syscall_num)
{
    restricted_syscall *ptr;
    int counter;
    assert(list);

    counter = 0;
    ptr = list->head;
    while (counter < list->size)
    {
        if (ptr->syscall.syscall_num == syscall_num)
        {
            return ptr;
        }
        counter++;
        ptr = ptr->next;
    }
    return NULL;
}

void destruct_restricted_syscalls_list(restricted_syscalls_list *list)
{
    restricted_syscall *delNode;
    assert(list);

    while (list->size > 0)
    {
        delNode = list->head;
        list->head = (list->head)->next;
        delNode->next = NULL;
        free(delNode->syscall.syscall_name);
        while (!queue_is_empty(delNode->calls_per_sec))
        {
            dequeue(delNode->calls_per_sec);
        }
        queue_free(delNode->calls_per_sec);
        free(delNode);
        list->size--;
    }
    free(list);
    return;
}

void print_restricted_syscalls_list(restricted_syscalls_list *list)
{
    restricted_syscall *ptr;
    int counter;
    assert(list);

    counter = 0;
    ptr = list->head;
    printf("System calls for monitoring:\n");
    while (counter < list->size)
    {
        printf("System call name: %s\n", ptr->syscall.syscall_name);
        printf("System call number: %d\n", ptr->syscall.syscall_num);
        printf("System call max calls: %d\n", ptr->max_calls);
        printf("System call total calls in a second: %d\n", ptr->calls_per_sec->size);
        counter++;
        ptr = ptr->next;
    }

    return;
}

/***************   System calls Sequence List   ***************/

syscalls_sequence_list *init_syscalls_sequence_list()
{
    syscalls_sequence_list *list;

    list = (syscalls_sequence_list *)malloc(sizeof(syscalls_sequence_list));
    if (!list)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for syscalls sequence list.\n");
        exit(EXIT_FAILURE);
    }

    list->size = 0;
    list->head = NULL;

    return list;
}

void insert_syscalls_sequence_list(syscalls_sequence_list *list, const char *syscall_name, int syscall_num)
{
    syscall_sequence *newNode, *ptr;
    int counter;

    assert(list && syscall_name);

    newNode = (syscall_sequence *)malloc(sizeof(syscall_sequence));
    if (!newNode)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for a syscall of the sequence.\n");
        exit(EXIT_FAILURE);
    }

    newNode->syscall.syscall_name = strdup(syscall_name);
    newNode->syscall.syscall_num = syscall_num;
    newNode->next = NULL;
    if (list->size == 0)
    {
        list->head = newNode;
        list->size++;
        return;
    }

    ptr = list->head;
    counter = 1;
    while (counter < list->size)
    {
        ptr = ptr->next;
        counter++;
    }
    ptr->next = newNode;
    list->size++;
    return;
}

void destruct_syscalls_sequence_list(syscalls_sequence_list *list)
{
    syscall_sequence *delNode;
    assert(list);

    while (list->size > 0)
    {
        delNode = list->head;
        list->head = (list->head)->next;
        delNode->next = NULL;
        free(delNode->syscall.syscall_name);
        free(delNode);
        list->size--;
    }
    free(list);
    return;
}

void print_syscalls_sequence_list(syscalls_sequence_list *list)
{
    syscall_sequence *ptr;
    int counter;
    assert(list);

    counter = 0;
    ptr = list->head;
    printf("Sequence:");
    while (counter < list->size)
    {
        printf("  %s", ptr->syscall.syscall_name);
        counter++;
        ptr = ptr->next;
    }
    printf("\n");

    return;
}

/***************   Access control system functionality   ***************/

int read_instructions_file(char *filename, restricted_syscalls_list *list, syscalls_sequence_list *seq)
{
    FILE *fp;
    char *syscall_name, *max_syscall_calls_s;
    int max_syscall_calls_i;
    char line[MAX_LINE_SIZE];
    int syscall_num;
    int isSequence;

    assert(filename && list && seq);
    fp = fopen(filename, "r");
    if (!fp)
    {
        fprintf(stderr, "ERROR: Failed to open \"%s\" file.\n", filename);
        return 0;
    }

    isSequence = 1;

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        /* Read restricted syscalls */
        if (!isSequence)
        {
            syscall_name = strtok(line, " \r\t\v\n");
            if (syscall_name == NULL)
                continue;
            max_syscall_calls_s = strtok(NULL, " \r\t\v\n");
            max_syscall_calls_i = atoi(max_syscall_calls_s);
            syscall_num = get_syscall_num(syscall_name);
            if (syscall_num != -1)
            {
                insert_restricted_syscalls_list(list, syscall_name, get_syscall_num(syscall_name), max_syscall_calls_i);
            }
        }
        else /* Read system calls sequence */
        {
            syscall_name = strtok(line, " \r\t\v\n");
            while (syscall_name != NULL)
            {
                syscall_num = get_syscall_num(syscall_name);

                if (syscall_num != -1)
                {
                    insert_syscalls_sequence_list(seq, syscall_name, syscall_num);
                }
                syscall_name = strtok(NULL, " \r\t\v\n");
            }

            isSequence = 0;
        }
    }

    fclose(fp);
    return 1;
}

int checkViolation(restricted_syscall *res_syscall)
{
    double first_call, last_call;
    assert(res_syscall);
    /*  Reaching here means a restricted syscall was called
        so calls_per_sec can't be empty */
    first_call = res_syscall->calls_per_sec->head->val;
    last_call = res_syscall->calls_per_sec->tail->val;
    while (!queue_is_empty(res_syscall->calls_per_sec) && (last_call - first_call) > 1)
    {
        dequeue(res_syscall->calls_per_sec);
        first_call = res_syscall->calls_per_sec->head->val;
    }
    /* printf("Last call - first call == %f\n", last_call - first_call); */
    if (res_syscall->calls_per_sec->size > res_syscall->max_calls)
    {
        return 1;
    }

    return 0;
}

int enable_access_control(syscalls_sequence_list *seq, queue_t *latest_syscalls)
{
    syscall_sequence *ptr1;
    node_t *ptr2;

    assert(seq && latest_syscalls);

    if (seq->size != latest_syscalls->size)
        return 0;

    ptr1 = seq->head;
    ptr2 = latest_syscalls->head;

    while (ptr1 != NULL && ptr1->syscall.syscall_num == (int)ptr2->val)
    { /* If ptr1 == NULL then ptr2 == NULL as seq and latest_syscalls have the same size */
        ptr1 = ptr1->next;
        ptr2 = ptr2->next;
    }

    if (ptr1 == NULL) /* Found the sequence so return 1 */
        return 1;

    return 0;
}

void execute_program(char **exec, restricted_syscalls_list *list, syscalls_sequence_list *seq)
{
    pid_t pid;
    int status;
    struct user_regs_struct regs;
    int in_call;
    int enable;
    clock_t clock_ticks;
    restricted_syscall *ptr_syscall;
    queue_t *latest_syscalls;

    assert(exec && list && seq);

    in_call = 0;
    enable = 0;
    pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "ERROR: Forking child process failed\n");
        exit(1);
    }
    else if (pid == 0)
    {   /* Child */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (execvp(*exec, exec) < 0)
        { /* execute the executable file  */
            fprintf(stderr, "ERROR: exec failed\n");
            exit(1);
        }
    }
    else
    {
        wait(&status);
        latest_syscalls = queue_init();
        if (seq->size == 0)
        {
            enable = 1;
            printf("Access control system is enabled.\n");
        }

        while (status == 1407)
        {
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            clock_ticks = clock();
            if (!in_call) /* ptrace pauses at the start and the end of the system call */
            {
                printf("SystemCall %ld called with %ld, %ld, %ld\n", regs.orig_eax, regs.ebx, regs.ecx, regs.edx); /* regs.orig_eax -> systemcall number */

                if (enable)
                {
                    ptr_syscall = lookup_restricted_syscalls_list(list, regs.orig_eax);
                    if (ptr_syscall != NULL)                                            /* Checks if a restricted systemcall was called */
                    {
                        enqueue(ptr_syscall->calls_per_sec, (double)clock_ticks / CLOCKS_PER_SEC); /* If a restricted syscall was called add it in queue for the violation check */
                        if (checkViolation(ptr_syscall))
                        {
                            printf("Restricted system call with name \"%s\" and number \"%d\" violated the max calls \"%d\" as it was called %d times a second.\n",
                                   ptr_syscall->syscall.syscall_name, ptr_syscall->syscall.syscall_num, ptr_syscall->max_calls, ptr_syscall->calls_per_sec->size);
                        }
                    }
                }
                else
                {
                    enqueue(latest_syscalls, regs.orig_eax);
                    if (latest_syscalls->size > seq->size)
                    {
                        dequeue(latest_syscalls);
                    }
                    enable = enable_access_control(seq, latest_syscalls);
                    if (enable)
                    {
                        printf("Access control system is enabled.\n");
                    }
                }

                in_call = 1;
            }
            else
                in_call = 0;

            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&status);
        }

        while (latest_syscalls->size > 0)
        {
            dequeue(latest_syscalls);
        }
        queue_free(latest_syscalls);
    }
}

int main(int argc, char *argv[])
{
    char *exeName;
    char **exePtr;
    restricted_syscalls_list *list;
    syscalls_sequence_list *seq;

    if (argc != 3)
    {
        fprintf(stderr, "ERROR: Wrong arguments.\n");
        return 0;
    }
    printf("Executable to be traced: %s\nInstructions file: %s\n", argv[1], argv[2]);
    list = init_restricted_syscalls_list();
    seq = init_syscalls_sequence_list();
    if (!read_instructions_file(argv[2], list, seq))
    {
        fprintf(stderr, "ERROR: Failed to read instructions file \"%s\".\n", argv[2]);
        destruct_restricted_syscalls_list(list);
        destruct_syscalls_sequence_list(seq);
        return 0;
    }
    exeName = strdup(argv[1]);
    exePtr = &exeName;
    execute_program(exePtr, list, seq);
    print_syscalls_sequence_list(seq);
    print_restricted_syscalls_list(list);
    destruct_restricted_syscalls_list(list);
    destruct_syscalls_sequence_list(seq);
    free(exeName);
    return 1;
}

int get_syscall_num(char *syscall_name)
{
    char syscall_names[TOTAL_SYSCALLS][25] = {
        "restart_syscall",
        "exit",
        "fork",
        "read",
        "write",
        "open",
        "close",
        "waitpid",
        "creat",
        "link",
        "unlink",
        "execve",
        "chdir",
        "time",
        "mknod",
        "chmod",
        "lchown",
        "break",
        "oldstat",
        "lseek",
        "getpid",
        "mount",
        "umount",
        "setuid",
        "getuid",
        "stime",
        "ptrace",
        "alarm",
        "oldfstat",
        "pause",
        "utime",
        "stty",
        "gtty",
        "access",
        "nice",
        "ftime",
        "sync",
        "kill",
        "rename",
        "mkdir",
        "rmdir",
        "dup",
        "pipe",
        "times",
        "prof",
        "brk",
        "setgid",
        "getgid",
        "signal",
        "geteuid",
        "getegid",
        "acct",
        "umount2",
        "lock",
        "ioctl",
        "fcntl",
        "mpx",
        "setpgid",
        "ulimit",
        "oldolduname",
        "umask",
        "chroot",
        "ustat",
        "dup2",
        "getppid",
        "getpgrp",
        "setsid",
        "sigaction",
        "sgetmask",
        "ssetmask",
        "setreuid",
        "setregid",
        "sigsuspend",
        "sigpending",
        "sethostname",
        "setrlimit",
        "getrlimit",
        "getrusage",
        "gettimeofday",
        "settimeofday",
        "getgroups",
        "setgroups",
        "select",
        "symlink",
        "oldlstat",
        "readlink",
        "uselib",
        "swapon",
        "reboot",
        "readdir",
        "mmap",
        "munmap",
        "truncate",
        "ftruncate",
        "fchmod",
        "fchown",
        "getpriority",
        "setpriority",
        "profil",
        "statfs",
        "fstatfs",
        "ioperm",
        "socketcall",
        "syslog",
        "setitimer",
        "getitimer",
        "stat",
        "lstat",
        "fstat",
        "olduname",
        "iopl",
        "vhangup",
        "idle",
        "vm86old",
        "wait4",
        "swapoff",
        "sysinfo",
        "ipc",
        "fsync",
        "sigreturn",
        "clone",
        "setdomainname",
        "uname",
        "modify_ldt",
        "adjtimex",
        "mprotect",
        "sigprocmask",
        "create_module",
        "init_module",
        "delete_module",
        "get_kernel_syms",
        "quotactl",
        "getpgid",
        "fchdir",
        "bdflush",
        "sysfs",
        "personality",
        "afs_syscall",
        "setfsuid",
        "setfsgid",
        "_llseek",
        "getdents",
        "_newselect",
        "flock",
        "msync",
        "readv",
        "writev",
        "getsid",
        "fdatasync",
        "_sysctl",
        "mlock",
        "munlock",
        "mlockall",
        "munlockall",
        "sched_setparam",
        "sched_getparam",
        "sched_setscheduler",
        "sched_getscheduler",
        "sched_yield",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_rr_get_interval",
        "nanosleep",
        "mremap",
        "setresuid",
        "getresuid",
        "vm86",
        "query_module",
        "poll",
        "nfsservctl",
        "setresgid",
        "getresgid",
        "prctl",
        "rt_sigreturn",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigqueueinfo",
        "rt_sigsuspend",
        "pread64",
        "pwrite64",
        "chown",
        "getcwd",
        "capget",
        "capset",
        "sigaltstack",
        "sendfile",
        "getpmsg",
        "putpmsg",
        "vfork",
        "ugetrlimit",
        "mmap2",
        "truncate64",
        "ftruncate64",
        "stat64",
        "lstat64",
        "fstat64",
        "lchown32",
        "getuid32",
        "getgid32",
        "geteuid32",
        "getegid32",
        "setreuid32",
        "setregid32",
        "getgroups32",
        "setgroups32",
        "fchown32",
        "setresuid32",
        "getresuid32",
        "setresgid32",
        "getresgid32",
        "chown32",
        "setuid32",
        "setgid32",
        "setfsuid32",
        "setfsgid32",
        "pivot_root",
        "mincore",
        "madvise",
        "getdents64",
        "fcntl64",
        "",
        "",
        "gettid",
        "readahead",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "getxattr",
        "lgetxattr",
        "fgetxattr",
        "listxattr",
        "llistxattr",
        "flistxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "tkill",
        "sendfile64",
        "futex",
        "sched_setaffinity",
        "sched_getaffinity",
        "set_thread_area",
        "get_thread_area",
        "io_setup",
        "io_destroy",
        "io_getevents",
        "io_submit",
        "io_cancel",
        "fadvise64",
        "",
        "exit_group",
        "lookup_dcookie",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
        "remap_file_pages",
        "set_tid_address",
        "timer_create",
        "timer_settime",
        "timer_gettime",
        "timer_getoverrun",
        "timer_delete",
        "clock_settime",
        "clock_gettime",
        "clock_getres",
        "clock_nanosleep",
        "statfs64",
        "fstatfs64",
        "tgkill",
        "utimes",
        "fadvise64_64",
        "vserver",
        "mbind",
        "get_mempolicy",
        "set_mempolicy",
        "mq_open",
        "mq_unlink",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_notify",
        "mq_getsetattr",
        "kexec_load",
        "waitid",
        "",
        "add_key",
        "request_key",
        "keyctl",
        "ioprio_set",
        "ioprio_get",
        "inotify_init",
        "inotify_add_watch",
        "inotify_rm_watch",
        "migrate_pages",
        "openat",
        "mkdirat",
        "mknodat",
        "fchownat",
        "futimesat",
        "fstatat64",
        "unlinkat",
        "renameat",
        "linkat",
        "symlinkat",
        "readlinkat",
        "fchmodat",
        "faccessat",
        "pselect6",
        "ppoll",
        "unshare",
        "set_robust_list",
        "get_robust_list",
        "splice",
        "sync_file_range",
        "tee",
        "vmsplice",
        "move_pages",
        "getcpu",
        "epoll_pwait",
        "utimensat",
        "signalfd",
        "timerfd_create",
        "eventfd",
        "fallocate",
        "timerfd_settime",
        "timerfd_gettime",
        "signalfd4",
        "eventfd2",
        "epoll_create1",
        "dup3",
        "pipe2",
        "inotify_init1",
        "preadv",
        "pwritev",
        "rt_tgsigqueueinfo",
        "perf_event_open",
        "recvmmsg",
        "fanotify_init",
        "fanotify_mark",
        "prlimit64"};
    int counter;
    counter = 0;

    while (counter < TOTAL_SYSCALLS)
    {
        if (!strcmp(syscall_name, syscall_names[counter]))
            return counter;
        counter++;
    }
    return -1;
}