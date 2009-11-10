
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#define NUM_ELEMS(a) (sizeof(a)/sizeof((a)[0]))

#define CREATE_MASK(size) ((1<<(size))-1)

#define GET_BITS(reg, shift, mask) ( ((reg)>>(shift)) & (mask) )

#define SET_BITS(reg, shift, mask, field) \
    ( ( (reg) & ~((mask)<<(shift)) ) | (((field)&(mask))<<(shift)) )

#define MOD_BITS(reg, shift, mask, field) \
    ( (reg) = SET_BITS((reg), (shift), (mask), (field)) )

#define output(level, format, args...) \
    (OPTION(verbose) >= (level) ? fprintf(OPTION(output_file), format , ## args) : 0)

#define OPTION(x) (options. x)

#define MAX_BREAKPOINTS 8

#define I_MASK (1<<0)
#define R_MASK (1<<1)
#define W_MASK (1<<2)

#define IRW_MASK (I_MASK | R_MASK | W_MASK)
#define ADDR_MASK (~(Addr_t)IRW_MASK)

#define ADDR_FMT PRIxPTR

enum {
    out_quiet,
    out_normal,
    out_verbose,
};

typedef uintptr_t Addr_t;

struct bp_info {
    Addr_t   addr;
    unsigned irw;
    const char *irw_name;
    unsigned size_mask;
};

struct {
    unsigned num;
    struct bp_info *hw[MAX_BREAKPOINTS];
    struct bp_info info[MAX_BREAKPOINTS];
} bps;

struct {
    pid_t trace_pid;
} procs;

struct {
    int verbose;
    int attach;
    FILE *output_file;
} options;

static
const char *irw_name(unsigned irw)
{
    switch (irw & IRW_MASK) {
    case I_MASK: return "Instruction";
    case R_MASK: return "Read";
    case W_MASK: return "Write";
    default:     return "Hit";
    }
}

static
const char *signal_name(sig)
{
    switch (sig)
    {
#define SIG_0 0
#define RET_NAME(x) case x: return #x
        RET_NAME(SIG_0);
        RET_NAME(SIGHUP);
        RET_NAME(SIGINT);
        RET_NAME(SIGQUIT);
        RET_NAME(SIGILL);
        RET_NAME(SIGTRAP);
        RET_NAME(SIGABRT);
        RET_NAME(SIGBUS);
        RET_NAME(SIGFPE);
        RET_NAME(SIGKILL);
        RET_NAME(SIGUSR1);
        RET_NAME(SIGSEGV);
        RET_NAME(SIGUSR2);
        RET_NAME(SIGPIPE);
        RET_NAME(SIGALRM);
        RET_NAME(SIGTERM);
        RET_NAME(SIGSTKFLT);
        RET_NAME(SIGCHLD);
        RET_NAME(SIGCONT);
        RET_NAME(SIGSTOP);
        RET_NAME(SIGTSTP);
        RET_NAME(SIGTTIN);
        RET_NAME(SIGTTOU);
        RET_NAME(SIGURG);
        RET_NAME(SIGXCPU);
        RET_NAME(SIGXFSZ);
        RET_NAME(SIGVTALRM);
        RET_NAME(SIGPROF);
        RET_NAME(SIGWINCH);
        RET_NAME(SIGIO);
        RET_NAME(SIGPWR);
        RET_NAME(SIGSYS);
        default: return "unknown";
    }
}

static
void trace_cmd(char *argv[])
{
    pid_t child = fork();

    if ( child < 0 )
        error(EXIT_FAILURE, errno, "%s: fork %s", __func__, argv[0]);

    if ( child == 0 )  // run command in child process
    {
        long rc = ptrace(PTRACE_TRACEME);

        if (rc < 0) error(EXIT_FAILURE, errno, "%s: PTRACE_TRACEME '%s'", __func__, argv[0]);

        execvp(argv[0], argv);
        error(0, errno, "%s: execvp '%s'", __func__, argv[0]);
        _exit(EXIT_FAILURE);
    }
    else {
        procs.trace_pid = child;
    }
}

static
void attach_pid(pid_t pid)
{
    long rc = ptrace(PTRACE_ATTACH, pid);

    if (rc < 0) error(EXIT_FAILURE, errno, "%s: PTRACE_ATTACH %d", __func__, pid);
}

static
void continue_running(pid_t pid, int sig)
{
    long rc = ptrace(PTRACE_CONT, pid, (char*)1, sig);

    if (rc < 0 && errno != ESRCH)
        error(EXIT_FAILURE, errno, "%s: PTRACE_CONT %d sig %d", __func__, pid, sig);
}

static
void continue_syscall(pid_t pid)
{
    long rc = ptrace(PTRACE_SYSCALL, pid, (char*)1, 0);

    if (rc < 0 && errno != ESRCH)
        error(EXIT_FAILURE, errno, "%s: PTRACE_SYSCALL %d", __func__, pid);
}

static
void trace_clones(pid_t pid)
{
    long rc = ptrace(PTRACE_SETOPTIONS, pid, (char*)1, PTRACE_O_TRACEVFORK
                                                     | PTRACE_O_TRACECLONE);

    if (rc < 0) error(EXIT_FAILURE, errno, "%s: PTRACE_SETOPTIONS %d", __func__, pid);
}

static
const char *clone_name(int status)
{
    switch ( status >> 16 )
    {
        case PTRACE_EVENT_FORK:  return "fork";
        case PTRACE_EVENT_VFORK: return "vfork";
        case PTRACE_EVENT_CLONE: return "clone";
        default:                 return 0;
    }
}

static
pid_t get_clone_pid(pid_t pid)
{
    unsigned long new_pid = 0;

    long rc = ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) ;

    if (rc < 0) error(EXIT_FAILURE, errno, "%s: PTRACE_GETEVENTMSG %d", __func__, pid);

    return new_pid;
}

static
int my_waitpid(int *status)
{
    pid_t pid;

    do { pid = waitpid(-1, status, __WALL); } while ( pid == -1 && errno == EINTR );

    return pid;
}

static
void handle_stop(pid_t pid, int status, int sig)
{
    const char *cloned;
    static int initialized = 0;

    if ( ! initialized )
    {
        initialized = 1;

        trace_clones(pid);
        continue_running(pid, 0);
    }

    switch (sig)
    {
    case SIGTRAP:
        cloned = clone_name(status);
        if ( cloned )
        {
            pid_t new_pid = get_clone_pid(pid);

            output(out_normal, "%d %s %d\n", pid, cloned, new_pid);

            continue_running(pid, 0);

            continue_running(new_pid, 0);
        }
        else continue_running(pid, sig);  // deliver signal
        break;
    case SIGSTOP:
        continue_running(pid, 0);
        break;
    default:
        continue_running(pid, sig);  // deliver signal
    }
}

static
void main_loop(void)
{
    for (;;)
    {
        int status = 0;

        pid_t pid = my_waitpid(&status);

        if ( pid < 0 )
            error(EXIT_FAILURE, errno, "%s: waitpid\n", __func__);

        output(out_verbose, "%d waitpid status 0x%04x\n", pid, status);

        if ( WIFEXITED(status) )
        {
            int exit_status = WEXITSTATUS(status);

            output(out_normal, "%d exited %d\n", pid, exit_status);

            if (pid == procs.trace_pid) exit(exit_status);
        }
        else if ( WIFSIGNALED(status) )
        {
            int term_sig = WTERMSIG(status);

            output(out_normal, "%d terminated with %d %s\n",
                   pid, term_sig, signal_name(term_sig));

            if (pid == procs.trace_pid) exit(EXIT_SUCCESS);
        }
        else if ( WIFSTOPPED(status) )
        {
            int stop_sig = WSTOPSIG(status);

            output(out_normal, "%d stopped with %d %s\n",
                   pid, stop_sig, signal_name(stop_sig));

            handle_stop(pid, status, stop_sig);
        }
        else output(out_normal, "%d waitpid strange status 0x%x\n", pid, status);
    }
}

static
int get_number(const char *arg, Addr_t *value)
{
    if (arg)
    {
        char *endptr;
        *value = strtoull(arg, &endptr, 0);
        return *arg != 0 && *endptr == 0;
    }
    *value = 0;
    return 0;
}

static
char *separate(char *s, char sep)
{
    if (s) s = strchr(s, sep);
    if (s) *s++ = 0;  // replace sep with NUL
    return s;
}

static
void get_addr(const char *option, char *arg, unsigned irw)
{
    struct bp_info *bp = &bps.info[bps.num++];
    const char *sz = separate(arg, ',');
    Addr_t addr;
    Addr_t size;

    if ( bps.num > NUM_ELEMS(bps.info) )
        error(EXIT_FAILURE, 0, "cannot have more than %d breakpoints\n", NUM_ELEMS(bps.info));

    if ( ! get_number(arg, &addr) )
        error(EXIT_FAILURE, 0, "invalid address '%s' for option '%s'\n", arg, option);

    bp->addr = addr & ADDR_MASK;
    bp->irw  = irw  & IRW_MASK;
    bp->irw_name = irw_name(bp->irw);

    if ( sz ) {
        if ( ! get_number(sz, &size) )
            error(EXIT_FAILURE, 0, "invalid size '%s' for option '%s'\n", sz, option);
        if ( size & (size-1) )
            error(EXIT_FAILURE, 0, "invalid size '%s' for option '%s', size must be a power of 2\n", sz, option);
        bp->size_mask = IRW_MASK;
    }
    else {
        bp->size_mask = size;
    }
}

static
void usage(FILE *fp, int status)
{
    fprintf( fp,
        "usage: trace [-i addr] [-rw addr] [-o file] -p pid\n"
        "       trace [-i addr] [-rw addr] [-o file] command [arg ...]\n"
        "options:\n"
        "\t-i addr -- trace instruction access\n"
        "\t-r addr -- trace read access\n"
        "\t-w addr -- trace write access\n"
        "\t-rw addr -- trace read or write access\n"
        "\t-q      -- quiet mode\n"
        "\t-v      -- verbose mode\n"
        "\t-o file -- send trace output to FILE instead of stderr\n"
        "\t-p pid  -- trace process with process id PID\n"
        "\t-E var=val -- put var=val in the environment for command\n"
        "\t-E var     -- remove var from the environment for command\n"
        );
    exit(status);
}

#if 0
#define dump_args(first, argc, argv) dump_args(first, argc, argv, #argv)
#define dump_option(name) dump_option(name)
#else
#define dump_args(first, argc, argv)
#define dump_option(name)
#endif

void (dump_args)(int first, int argc, char *argv[], const char *varname)
{
    int i;
    for ( i = first; i < argc; i++ ) {
        fprintf(stderr, "%s[%d]: '%s'\n", varname, i, argv[i]);
    }
}

void (dump_option)(const char *name)
{
    fprintf(stderr, "%s: '%s' %d\n", name, optarg, optind);
}

#define option_with_space(argv) (optarg == (argv)[optind-1])
#define remaining(argc) ((argc) - optind)

int main(int argc, char *argv[])
{
    int opt;

    OPTION(verbose)     = 1;
    OPTION(output_file) = stderr;

    while ((opt = getopt(argc, argv, "+i:r:w:c:C:d:p:qvh")) != -1)
    {
        switch (opt) {
        case 'i':
            dump_option("i");
            get_addr("i", optarg, I_MASK);
            break;
        case 'r':
            if ( ! option_with_space(argv) && *optarg == 'w')  // case 'rw'
            {
                if ( *++optarg == 0 ) optarg = argv[optind++];  // skip over 'w'
                dump_option("rw");
                get_addr("rw", optarg, R_MASK | W_MASK);
            }
            else
            {
                dump_option("r");
                get_addr("r", optarg, R_MASK);
            }
            break;
        case 'w':
            dump_option("w");
            get_addr("w", optarg, W_MASK);
            break;
        case 'c':
            dump_option("c");
            break;
        case 'C':
            dump_option("C");
            break;
        case 'd':
            dump_option("d");
            break;
        case 'p':
            dump_option("p");
            OPTION(attach) = 1;
            procs.trace_pid = atoi(optarg);
            if ( procs.trace_pid <= 0 )
                error(EXIT_FAILURE, 0, "invalid PID '%s' for option 'p'\n", optarg);
            break;
        case 'q':
            OPTION(verbose) = 0;
            break;
        case 'v':
            OPTION(verbose)++;
            break;
        case 'h':
            usage(stdout, EXIT_SUCCESS);
            break;
        default:
            usage(stderr, EXIT_FAILURE);
        }
    }

    dump_args(optind, argc, argv);

    if ( remaining(argc) > 0 && ! OPTION(attach) )
    {
        trace_cmd(&argv[optind]);
    }
    else if ( remaining(argc) == 0 && OPTION(attach) )
    {
        attach_pid(procs.trace_pid);
    }
    else usage(stderr, EXIT_FAILURE);

    main_loop();

    return EXIT_SUCCESS;
}

