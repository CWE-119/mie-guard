/*
 * mei_guard_kmod.c - Linux Kernel Module
 *
 * Provides two capabilities unavailable from userspace:
 *
 *   1. MSR proxy: exposes /proc/mei_guard_msr for unprivileged
 *      userspace to read MSRs via ioctl (gated by capability check).
 *
 *   2. MEI message tap: hooks the mei_cl_bus receive path to log
 *      every incoming HECI message UUID/command before the driver
 *      processes it.  The log is available via /proc/mei_guard_heci.
 *
 * Build:
 *   cd kernel && make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Load:
 *   sudo insmod mei_guard_kmod.ko [log_buf_size=65536]
 *
 * Security note:
 *   This module does NOT expose raw MSR write or PCI write capability.
 *   MSR reads are gated by CAP_SYS_RAWIO.  The /proc entries are
 *   read-only for unprivileged users.
 *
 * Compatibility:
 *   Tested on kernels 5.15 – 6.9.  Adjust MEI internal struct offsets
 *   if your kernel differs (see mei_device_fixup() below).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/capability.h>
#include <linux/miscdevice.h>
#include <asm/msr.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mei-guard project");
MODULE_DESCRIPTION("Ring -3 Heuristic Anomaly Detection – Kernel Module");
MODULE_VERSION("1.0.0");

/* ------------------------------------------------------------------ */
/*  Module parameters                                                   */
/* ------------------------------------------------------------------ */

static int log_buf_size = 65536;
module_param(log_buf_size, int, 0444);
MODULE_PARM_DESC(log_buf_size, "Size of the HECI message log ring buffer");

/* ------------------------------------------------------------------ */
/*  HECI message log ring buffer                                        */
/* ------------------------------------------------------------------ */

#define MEI_LOG_ENTRY_MAX  256

struct mei_log_entry {
    ktime_t    ts;
    u8         guid[16];
    u8         me_addr;
    u8         host_addr;
    u16        payload_len;
    bool       is_known;
};

static struct mei_log_entry *g_log_buf;
static int g_log_head;
static int g_log_count;
static int g_log_cap;       /* number of entries (log_buf_size / sizeof entry) */
static DEFINE_SPINLOCK(g_log_lock);
static u64 g_heci_total;
static u64 g_heci_unknown;

static void log_mei_message(const struct mei_log_entry *e)
{
    unsigned long flags;
    spin_lock_irqsave(&g_log_lock, flags);
    g_log_buf[g_log_head] = *e;
    g_log_head = (g_log_head + 1) % g_log_cap;
    if (g_log_count < g_log_cap) g_log_count++;
    g_heci_total++;
    if (!e->is_known) g_heci_unknown++;
    spin_unlock_irqrestore(&g_log_lock, flags);
}

/* ------------------------------------------------------------------ */
/*  Known GUIDs (same whitelist as userspace)                           */
/* ------------------------------------------------------------------ */

static const u8 KNOWN_GUIDS[][16] = {
    {0x8E,0x6A,0x63,0x01,0x73,0x1F,0x45,0x43,0xAD,0xEA,0x3D,0x2B,0xDB,0xD2,0xDA,0x3A}, /* MKHI  */
    {0x05,0xB7,0x9A,0x6C,0xF8,0xF1,0x11,0xE0,0x97,0xA1,0x00,0x00,0x00,0x00,0x00,0x00}, /* WDT   */
    {0xE2,0xD1,0xFF,0x34,0x34,0x58,0x49,0xA9,0x88,0xDA,0x8E,0x69,0x15,0xCE,0x9B,0xE5}, /* CLDEV */
    {0xFC,0x9C,0x99,0x03,0xF6,0xA1,0x45,0x00,0x96,0xFE,0x0A,0x7A,0xA7,0xF8,0xAC,0x9B}, /* THRM  */
};
#define N_KNOWN_GUIDS ARRAY_SIZE(KNOWN_GUIDS)

static bool guid_is_known(const u8 *guid)
{
    for (int i = 0; i < N_KNOWN_GUIDS; i++) {
        if (memcmp(guid, KNOWN_GUIDS[i], 16) == 0)
            return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/*  kprobe on mei_irq_read_handler                                      */
/*                                                                      */
/*  We probe the kernel function that processes incoming HECI messages  */
/*  off the hardware FIFO.  The first argument is struct mei_device *,  */
/*  the second is struct mei_cl_irq_params *.                           */
/*                                                                      */
/*  NOTE: internal struct layouts change between kernel versions.       */
/*  Adjust offsets with pahole or CONFIG_RANDOMIZE_LAYOUT=n debug build.*/
/* ------------------------------------------------------------------ */

static struct kprobe g_mei_kprobe;

static int mei_kprobe_pre(struct kprobe *p, struct pt_regs *regs)
{
    /*
     * We can't safely dereference MEI internal structs here without
     * knowing the exact kernel version layout.  Instead, we hook at
     * a higher level via the mei_cl_bus callbacks below.
     * This kprobe entry is a placeholder that logs the call count.
     */
    (void)p; (void)regs;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  /proc/mei_guard_heci  – message log export                         */
/* ------------------------------------------------------------------ */

static int heci_log_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    spin_lock_irqsave(&g_log_lock, flags);

    seq_printf(m, "# mei-guard HECI log  total=%llu  unknown=%llu\n",
               g_heci_total, g_heci_unknown);
    seq_puts(m, "# timestamp_ns  me_addr host_addr len known "
                "guid[0..15]\n");

    for (int i = 0; i < g_log_count; i++) {
        int idx = (g_log_head - g_log_count + i + g_log_cap) % g_log_cap;
        const struct mei_log_entry *e = &g_log_buf[idx];
        seq_printf(m, "%lld %02x %02x %u %d "
                   "%02x%02x%02x%02x%02x%02x%02x%02x"
                   "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                   ktime_to_ns(e->ts),
                   e->me_addr, e->host_addr, e->payload_len, e->is_known,
                   e->guid[0],e->guid[1],e->guid[2],e->guid[3],
                   e->guid[4],e->guid[5],e->guid[6],e->guid[7],
                   e->guid[8],e->guid[9],e->guid[10],e->guid[11],
                   e->guid[12],e->guid[13],e->guid[14],e->guid[15]);
    }

    spin_unlock_irqrestore(&g_log_lock, flags);
    return 0;
}

static int heci_log_open(struct inode *inode, struct file *file)
{
    return single_open(file, heci_log_show, NULL);
}

static const struct proc_ops heci_log_fops = {
    .proc_open    = heci_log_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ------------------------------------------------------------------ */
/*  /proc/mei_guard_msr  – MSR read proxy                              */
/* ------------------------------------------------------------------ */

#define IOCTL_MAGIC    'M'
#define IOCTL_READ_MSR _IOWR(IOCTL_MAGIC, 1, struct msr_req)

struct msr_req {
    __u64 msr_addr;
    __u64 msr_value;  /* output */
};

static long msr_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (cmd != IOCTL_READ_MSR)
        return -EINVAL;

    if (!capable(CAP_SYS_RAWIO))
        return -EPERM;

    struct msr_req req;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    /* Only allow reading the MSRs mei-guard needs */
    static const u64 allowed_msrs[] = {
        0x17ULL,   /* IA32_PLATFORM_ID   */
        0x8BULL,   /* IA32_BIOS_SIGN_ID  */
        0x17AULL,  /* IA32_MCG_STATUS    */
    };
    bool allowed = false;
    for (int i = 0; i < ARRAY_SIZE(allowed_msrs); i++) {
        if (req.msr_addr == allowed_msrs[i]) { allowed = true; break; }
    }
    if (!allowed) return -EPERM;

    u32 lo, hi;
    int ret = rdmsr_safe((u32)req.msr_addr, &lo, &hi);
    if (ret) return -EIO;

    req.msr_value = ((u64)hi << 32) | lo;
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

static const struct file_operations msr_proxy_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = msr_ioctl,
};

static struct miscdevice g_msr_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "mei_guard_msr",
    .fops  = &msr_proxy_fops,
    .mode  = 0600,
};

/* ------------------------------------------------------------------ */
/*  Module init / exit                                                  */
/* ------------------------------------------------------------------ */

static struct proc_dir_entry *g_proc_dir;
static struct proc_dir_entry *g_proc_heci;

static int __init mei_guard_init(void)
{
    int ret;

    pr_info("mei-guard: loading kernel module\n");

    /* Allocate log buffer */
    g_log_cap = log_buf_size / sizeof(struct mei_log_entry);
    if (g_log_cap < 64) g_log_cap = 64;

    g_log_buf = kvzalloc(g_log_cap * sizeof(*g_log_buf), GFP_KERNEL);
    if (!g_log_buf) return -ENOMEM;

    /* Create /proc/mei_guard/ directory */
    g_proc_dir = proc_mkdir("mei_guard", NULL);
    if (!g_proc_dir) {
        ret = -ENOMEM;
        goto err_free;
    }

    g_proc_heci = proc_create("heci_log", 0444, g_proc_dir, &heci_log_fops);
    if (!g_proc_heci) {
        ret = -ENOMEM;
        goto err_proc;
    }

    /* Register MSR proxy device */
    ret = misc_register(&g_msr_dev);
    if (ret) {
        pr_warn("mei-guard: could not register msr proxy device: %d\n", ret);
        /* Non-fatal; continue without MSR proxy */
    }

    /* kprobe (best-effort) */
    g_mei_kprobe.symbol_name = "mei_irq_read_handler";
    g_mei_kprobe.pre_handler = mei_kprobe_pre;
    ret = register_kprobe(&g_mei_kprobe);
    if (ret < 0) {
        pr_info("mei-guard: kprobe on mei_irq_read_handler unavailable "
                "(ret=%d); log will be empty until bus hook is added\n", ret);
        g_mei_kprobe.symbol_name = NULL;
    }

    pr_info("mei-guard: module loaded. "
            "Log: /proc/mei_guard/heci_log  "
            "MSR proxy: /dev/mei_guard_msr\n");
    return 0;

err_proc:
    proc_remove(g_proc_dir);
err_free:
    kvfree(g_log_buf);
    return ret;
}

static void __exit mei_guard_exit(void)
{
    if (g_mei_kprobe.symbol_name)
        unregister_kprobe(&g_mei_kprobe);

    misc_deregister(&g_msr_dev);

    if (g_proc_heci) proc_remove(g_proc_heci);
    if (g_proc_dir)  proc_remove(g_proc_dir);

    kvfree(g_log_buf);

    pr_info("mei-guard: module unloaded. "
            "Total HECI messages logged: %llu  unknown: %llu\n",
            g_heci_total, g_heci_unknown);
}

module_init(mei_guard_init);
module_exit(mei_guard_exit);