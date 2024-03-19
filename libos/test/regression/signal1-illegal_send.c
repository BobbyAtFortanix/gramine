/* Copyright 2018 Fortanix, Inc. */

/* Regression test for ZIRC-877: signals sent to the parent process
 * should not also be sent to the current process.
 *
 * In failing cases, this test may also expose ZIRC-876. But in
 * passing cases it should not.
 */

#define _GNU_SOURCE
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/syscall.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <sched.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <ucontext.h>

#define LOOPS 100000

#define DECLARE_SIGNAL_HANDLER(__sig__)                                             \
            static volatile int __sig__##_received = 0;                             \
            static void __sig__##_handler(int sig, siginfo_t *info, void *uctx) {   \
                char sigtxt[64] = {0};                                              \
                assert(sig == (__sig__));                                           \
                if(info != NULL) {                                                  \
                    char txt[64];                                                   \
                    char addr[96];                                                  \
                    const char *si_code = "";                                       \
                    addr[0] = 0;                                                    \
                    if((__sig__) == SIGILL){                                        \
                        snprintf(sigtxt, sizeof sigtxt, "SIGILL(%d)", SIGILL);      \
                        switch(info->si_code){                                      \
                            case ILL_ILLOPC: si_code = "ILL_ILLOPC - Illegal opcode"; break;  \
                            case ILL_ILLOPN: si_code = "ILL_ILLOPN - Illegal operand"; break; \
                            case ILL_ILLADR: si_code = "ILL_ILLADR - Illegal addressing mode"; break; \
                            case ILL_ILLTRP: si_code = "ILL_ILLTRP - Illegal trap"; break; \
                            case ILL_PRVOPC: si_code = "ILL_PRVOPC - Privileged opcode"; break; \
                            case ILL_PRVREG: si_code = "ILL_PRVREG - Privileged register"; break; \
                            case ILL_COPROC: si_code = "ILL_COPROC - Coprocessor error"; break; \
                            case ILL_BADSTK: si_code = "ILL_BADSTK - Internal stack error"; break; \
                            default:                                                \
                                snprintf(txt, sizeof(txt), "unknown:%d", info->si_code); \
                                si_code = (const char*)txt;                         \
                                break;                                              \
                        }                                                           \
                        snprintf(addr, sizeof(addr), "si_addr:%p, si_addr_lsb:%d, ",\
                                 info->si_addr, info->si_addr_lsb);                 \
                    }else if((__sig__) == SIGFPE){                                  \
                        snprintf(sigtxt, sizeof sigtxt, "SIGFPE(%d)", SIGFPE);      \
                        switch(info->si_code){                                      \
                            case FPE_INTDIV  : si_code = "FPE_INTDIV - Integer divide by zero"; break; \
                            case FPE_INTOVF  : si_code = "FPE_INTOVF - Integer overflow"; break; \
                            case FPE_FLTDIV  : si_code = "FPE_FLTDIV - Floating point divide by zero"; break; \
                            case FPE_FLTOVF  : si_code = "FPE_FLTOVF - Floating point overflow"; break; \
                            case FPE_FLTUND  : si_code = "FPE_FLTUND - Floating point underflow"; break; \
                            case FPE_FLTRES  : si_code = "FPE_FLTRES - Floating point inexact result"; break; \
                            case FPE_FLTINV  : si_code = "FPE_FLTINV - Floating point invalid operation"; break; \
                            case FPE_FLTSUB  : si_code = "FPE_FLTSUB - Subscript out of range"; break; \
                            case FPE_FLTUNK  : si_code = "FPE_FLTUNK - Undiagnosed floating-point exception"; break; \
                            case FPE_CONDTRAP: si_code = "FPE_CONDTRAP - Trap on condition"; break; \
                            default:                                                \
                                snprintf(txt, sizeof(txt), "unknown:%d", info->si_code); \
                                si_code = (const char*)txt;                         \
                                break;                                              \
                        }                                                           \
                        snprintf(addr, sizeof(addr), "si_addr:%p, si_addr_lsb:%d, ",\
                                 info->si_addr, info->si_addr_lsb);                 \
                    } else if((__sig__) == SIGSEGV){                                \
                        snprintf(sigtxt, sizeof sigtxt, "SIGSEGV(%d)", SIGSEGV);    \
                        switch(info->si_code){                                      \
                            case SEGV_MAPERR : si_code = "SEGV_MAPERR - Address not mapped to object"; break; \
                            case SEGV_ACCERR : si_code = "SEGV_ACCERR - Invalid permissions for mapped object"; break; \
                            case SEGV_BNDERR : si_code = "SEGV_BNDERR - Bounds checking failure"; break; \
                            case SEGV_PKUERR : si_code = "SEGV_PKUERR - Protection key checking failure"; break; \
                            case SEGV_ACCADI : si_code = "SEGV_ACCADI - ADI not enabled for mapped object"; break; \
                            case SEGV_ADIDERR: si_code = "SEGV_ADIDERR - Disrupting MCD error"; break; \
                            case SEGV_ADIPERR: si_code = "SEGV_ADIPERR - Precise MCD exception"; break; \
                            default:                                                \
                                snprintf(txt, sizeof(txt), "unknown:%d", info->si_code); \
                                si_code = (const char*)txt;                         \
                                break;                                              \
                        }                                                           \
                        snprintf(addr, sizeof(addr), "si_addr:%p, si_addr_lsb:%d, ",\
                                 info->si_addr, info->si_addr_lsb);                 \
                    } else if((__sig__) == SIGBUS){                                 \
                        snprintf(sigtxt, sizeof sigtxt, "SIGBUS(%d)", SIGBUS);      \
                        switch(info->si_code){                                      \
                            case BUS_ADRALN   : si_code = "BUS_ADRALN - Invalid address alignment"; break; \
                            case BUS_ADRERR   : si_code = "BUS_ADRERR - Non-existant physical address"; break; \
                            case BUS_OBJERR   : si_code = "BUS_OBJERR - Object specific hardware error"; break; \
                            case BUS_MCEERR_AR: si_code = "BUS_MCEERR_AR - Hardware memory error: action required"; break; \
                            case BUS_MCEERR_AO: si_code = "BUS_MCEERR_AO - Hardware memory error: action optional"; break; \
                            default:                                                \
                                snprintf(txt, sizeof(txt), "unknown:%d", info->si_code); \
                                si_code = (const char*)txt;                         \
                                break;                                              \
                        }                                                           \
                        snprintf(addr, sizeof(addr), "si_addr:%p, si_addr_lsb:%d, ",\
                                 info->si_addr, info->si_addr_lsb);                 \
                    } else {                                                        \
                        snprintf(sigtxt, sizeof sigtxt, "SIGBUS(%d)", sig);         \
                    }                                                               \
                    fprintf(stderr, "%s(%4u): sig: %s, %s"                          \
                            "si_signo: %d, si_errno: %d, si_code: %d(%s)\n",        \
                            __func__, __LINE__, sigtxt, addr,                       \
                            info->si_signo, info->si_errno, info->si_code, si_code);\
                    if(expected_code == info->si_code &&                            \
                        expected_signal == sig){                                    \
                        test_case_passed = true;                                    \
                    }else{                                                          \
                        if(expected_signal != sig){                                 \
                            fprintf(stderr, "Expected signal %d, got signal %s\n",  \
                                   expected_signal, sigtxt);                        \
                        }                                                           \
                        if(expected_code != info->si_code){                         \
                            fprintf(stderr, "Signal %s had unexpected code: %d "    \
                                   "(exp: %d)\n",                                   \
                                   sigtxt, info->si_code, expected_code);           \
                        }                                                           \
                        test_case_passed = false;                                   \
                    }                                                               \
                } else {                                                            \
                    snprintf(sigtxt, sizeof sigtxt, "SIGBUS(%d)", sig);             \
                }                                                                   \
                if(uctx != NULL){                                                   \
                    ucontext_t *ucontext = (ucontext_t *)uctx;                      \
                    fprintf(stderr, "Signal %s handled with code %d, "              \
                                    "REG_RIP: 0x%llx\n",                            \
                                    sigtxt, info->si_code,                          \
                                    ucontext->uc_mcontext.gregs[REG_RIP]);          \
                    ucontext->uc_mcontext.gregs[REG_RIP] += rip_increment;          \
                    fprintf(stderr, "REG_ERR: 0x%llx, REG_TRAPNO: 0x%llx, "         \
                                    "REG_OLDMASK: 0x%llx, REG_CR2: 0x%llx\n",       \
                                    ucontext->uc_mcontext.gregs[REG_ERR    ],       \
                                    ucontext->uc_mcontext.gregs[REG_TRAPNO ],       \
                                    ucontext->uc_mcontext.gregs[REG_OLDMASK],       \
                                    ucontext->uc_mcontext.gregs[REG_CR2    ]        \
                           );                                                       \
                }                                                                   \
                __sig__##_received = 1;                                             \
            }
#define IS_SIGNAL_RECEIVED(__sig__)                         \
            (__sig__##_received != 0)
#define INSTALL_SIGNAL_HANDLER(__sig__)                     \
            instal_signal_handler((__sig__), __sig__##_handler) /* ; */

/*
 *     Signal      Standard   Action   Comment
       ────────────────────────────────────────────────────────────────────────
       SIGBUS       P2001      Core    Bus error (bad memory access)
       SIGCHLD      P1990      Ign     Child stopped or terminated
       SIGCLD         -        Ign     A synonym for SIGCHLD
       SIGCONT      P1990      Cont    Continue if stopped
       SIGEMT         -        Term    Emulator trap
       SIGFPE       P1990      Core    Floating-point exception
       SIGHUP       P1990      Term    Hangup detected on controlling terminal
                                       or death of controlling process
       SIGILL       P1990      Core    Illegal Instruction
       SIGINFO        -                A synonym for SIGPWR
       SIGINT       P1990      Term    Interrupt from keyboard
       SIGIO          -        Term    I/O now possible (4.2BSD)
       SIGIOT         -        Core    IOT trap. A synonym for SIGABRT
 //    SIGKILL      P1990      Term    Kill signal
       SIGLOST        -        Term    File lock lost (unused)
       SIGPIPE      P1990      Term    Broken pipe: write to pipe with no
                                       readers; see pipe(7)
       SIGPOLL      P2001      Term    Pollable event (Sys V).
                                       Synonym for SIGIO
       SIGPROF      P2001      Term    Profiling timer expired
       SIGPWR         -        Term    Power failure (System V)
       SIGQUIT      P1990      Core    Quit from keyboard
       SIGSEGV      P1990      Core    Invalid memory reference
       SIGSTKFLT      -        Term    Stack fault on coprocessor (unused)
 //    SIGSTOP      P1990      Stop    Stop process
       SIGTSTP      P1990      Stop    Stop typed at terminal
       SIGSYS       P2001      Core    Bad system call (SVr4);
                                       see also seccomp(2)

       SIGTERM      P1990      Term    Termination signal
       SIGTRAP      P2001      Core    Trace/breakpoint trap
       SIGTTIN      P1990      Stop    Terminal input for background process
       SIGTTOU      P1990      Stop    Terminal output for background process
       SIGUNUSED      -        Core    Synonymous with SIGSYS
       SIGURG       P2001      Ign     Urgent condition on socket (4.2BSD)
       SIGUSR1      P1990      Term    User-defined signal 1
       SIGUSR2      P1990      Term    User-defined signal 2
       SIGVTALRM    P2001      Term    Virtual alarm clock (4.2BSD)
       SIGXCPU      P2001      Core    CPU time limit exceeded (4.2BSD);
                                       see setrlimit(2)
       SIGXFSZ      P2001      Core    File size limit exceeded (4.2BSD);
                                       see setrlimit(2)
       SIGWINCH       -        Ign     Window resize signal (4.3BSD, Sun)
*/

int rip_increment; // How much the signal handler should increment %rip
int expected_code;
int expected_signal;
bool test_case_passed;

DECLARE_SIGNAL_HANDLER(SIGBUS);
DECLARE_SIGNAL_HANDLER(SIGFPE);
DECLARE_SIGNAL_HANDLER(SIGILL);
DECLARE_SIGNAL_HANDLER(SIGSEGV);
DECLARE_SIGNAL_HANDLER(SIGUSR1);
DECLARE_SIGNAL_HANDLER(SIGUSR2);

static int instal_signal_handler(int sig, void (*fn_handler)(int, siginfo_t *, void *))
{
    struct sigaction sa = {0};
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fn_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    errno = 0;
    if(sigaction(sig, &sa, NULL) == -1) {
        perror("sigaction");
        return -errno;
    }

    return 0;
}

static bool RunTestCase(int sig, int code, int instruction_size,
                        void (*test_fn)(uintptr_t param), uintptr_t param)
{
    fprintf(stderr, "Starting Test case for signal %d\n", sig);

    test_case_passed = false;
    expected_signal = sig;
    expected_code = code;
    rip_increment = instruction_size;

    test_fn(param);

    if (!test_case_passed) {
        fprintf(stderr, "Test case for signal %d failed\n", sig);
    }
    return test_case_passed;
}

static void Ud2(uintptr_t _unused)
{
    __asm__ volatile("ud2a" ::: "memory");
}

static void Segv(uintptr_t _unused)
{
    __asm__ volatile("xor %%rax, %%rax\n"
                     "mov %%rax, (%%rax)\n" ::: "rax", "memory");
}

static void DivZero(uintptr_t _unused)
{
    __asm__ volatile("xor %%rax, %%rax\n"
                     "div %%rax\n" ::: "rax", "memory");
}

#if 0
static void FpDivZero(uintptr_t _unused)
{
#if 0
    double x = 10.0, y = 0.0, result;

    __asm__ volatile (
        "fldl %1\n"         // Load x into ST0 (x is a double)
        "fdivl %2\n"        // Divide ST0 by y (y is a double)
        "fstpl %0"          // Store the result from ST0 to result (result is a double)
        : "=m" (result)     // Output: result variable
        : "m" (x), "m" (y)  // Input: x and y variables
    );
#else
    __asm__ volatile("fldz\n"           // Load 0.0 onto the FPU stack
                 "fchs\n"           // Change sign of ST0 (making it -0.0)
                 "fdivp\n"          // Divide by zero. divide st1 by st0 store result in st1 & pop the stack
                );
#endif
}
#endif

static void Kill(uintptr_t sig)
{
    pid_t mypid = getpid();
    int ret = kill(mypid, sig);
    __asm__ volatile("" ::: "memory");
    assert(ret == 0);
}

#if 0
static void SigQueue(uintptr_t sig)
{
    pid_t mypid = getpid();
    union sigval value = { .sival_int = 0 };
    int ret = sigqueue(mypid, sig, value);
    fprintf(stderr, "sigqueue ret: %d, errno: %d\n", ret, errno);
    assert(ret == 0);
}
#endif

int main (int argc, const char ** argv)
{
    printf("  argc: %d\n", argc);
    for(int i=0; i<argc; ++i) {
        printf("arg[%d]: '%s'\n", i, argv[i]);
    }
    printf("   pid: %d\n", getpid());
    INSTALL_SIGNAL_HANDLER(SIGBUS);
    INSTALL_SIGNAL_HANDLER(SIGFPE);
    INSTALL_SIGNAL_HANDLER(SIGILL);
    INSTALL_SIGNAL_HANDLER(SIGSEGV);
    INSTALL_SIGNAL_HANDLER(SIGUSR1);
    INSTALL_SIGNAL_HANDLER(SIGUSR2);

    bool success = true;

    if ((argc > 1) && (0 == strcasecmp(argv[1], "--do-external-signal-test"))) {
        usleep(300000); // sleep 300 sec
        // make sure no external signal was received
        if (IS_SIGNAL_RECEIVED(SIGILL)) {
            printf("FAILED: SIGILL was received\n");
            success = false;
        } else
            printf("      : SIGILL was NOT received\n");
        if (IS_SIGNAL_RECEIVED(SIGBUS)) {
            printf("FAILED: SIGBUS was received\n");
            success = false;
        } else
            printf("      : SIGBUS was NOT received\n");
        if (IS_SIGNAL_RECEIVED(SIGFPE)) {
            printf("FAILED: SIGFPE was received\n");
            success = false;
        } else
            printf("      : SIGFPE was NOT received\n");
        if (IS_SIGNAL_RECEIVED(SIGSEGV)) {
            printf("FAILED: SIGSEGV was received\n");
            success = false;
        } else
            printf("      : SIGSEGV was NOT received\n");

    } else {

        success = RunTestCase(SIGILL  , SI_USER    , 0, Kill     , SIGILL  ) && success;
        success = RunTestCase(SIGBUS  , SI_USER    , 0, Kill     , SIGBUS  ) && success;
        success = RunTestCase(SIGFPE  , SI_USER    , 0, Kill     , SIGFPE  ) && success;
        success = RunTestCase(SIGSEGV , SI_USER    , 0, Kill     , SIGSEGV ) && success;
        success = RunTestCase(SIGILL  , ILL_ILLOPC/*ILL_ILLOPN*/ , 2, Ud2      , 0       ) && success;
        success = RunTestCase(SIGFPE  , FPE_INTDIV , 3, DivZero  , 0       ) && success;
//        success = RunTestCase(SIGSEGV , SEGV_MAPERR, 3, Segv     , 0       ) && success;
//        success = RunTestCase(SIGFPE  , FPE_FLTDIV , 2, FpDivZero, 0       ) && success;
    }

    printf("signal1-illegal_send TEST %s\n", success?"OK":"FAILED");

    return 0;
}
