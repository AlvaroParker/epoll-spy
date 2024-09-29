#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if defined(__TARGET_ARCH_x86)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__x64_"
#elif defined(__TARGET_ARCH_s390)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__s390x_"
#elif defined(__TARGET_ARCH_arm64)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__arm64_"
#elif defined(__TARGET_ARCH_riscv)
#define SYSCALL_WRAPPER 1
#define SYS_PREFIX "__riscv_"
#else
#define SYSCALL_WRAPPER 0
#define SYS_PREFIX "__se_"
#endif

SEC("fmod_ret/" SYS_PREFIX "sys_epoll_ctl")
int monitor(int epfd, int op, int fd, struct epoll_event *event) {
    int pid = bpf_get_current_pid_tgid();
    bpf_printk("Pid of the function: %d", pid);
    return 0;
}
