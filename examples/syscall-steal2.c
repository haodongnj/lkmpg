/*
 * syscall-steal2.c
 *
 * System call "stealing" sample using kprobe handler.
 *
 * Using kprobes to hook on a specific system call.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h> /* which will have params */
#include <linux/cred.h> /* For current_uid() */
#include <linux/uidgid.h> /* For __kuid_val() */

/* UID we want to spy on - will be filled from the command line. */
static uid_t uid = -1;
module_param(uid, int, 0644);

static char *syscall_sym = "__x64_sys_openat";
module_param(syscall_sym, charp, 0644);

#if defined(CONFIG_KPROBES)
#include <linux/kprobes.h>

static int sys_call_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    if (__kuid_val(current_uid()) != uid) {
        return 0;
    }

    pr_info("%s called by %d\n", syscall_sym, uid);
    return 0;
}

struct kprobe syscall_kprobe = {
    .symbol_name = "__x64_sys_openat",
    .pre_handler = sys_call_kprobe_pre_handler,
};

#endif

static int __init syscall_steal_start(void)
{
#if defined(CONFIG_KPROBES)
    int err;
    syscall_kprobe.symbol_name = syscall_sym;
    err = register_kprobe(&syscall_kprobe);
    if (err) {
        pr_err("register_kprobe() failed: %d\n", err);
        return err;
    }

    pr_info("Spying on UID:%d\n", uid);

    return 0;
#else
    pr_err("Kprobes is not supported by this kernel\n");
    return -1;
#endif
}

static void __exit syscall_steal_end(void)
{
#if defined(CONFIG_KPROBES)
    unregister_kprobe(&syscall_kprobe);
#endif
}

module_init(syscall_steal_start);
module_exit(syscall_steal_end);

MODULE_LICENSE("GPL");
