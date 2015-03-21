#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/security.h>
#ifndef __init
#include <linux/init.h>
#endif

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netdevice.h>

#include <linux/cred.h>

//#define LINUX_VERSION_CODE 132640

//#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;
struct security_operations *ops = NULL;

#define swap_security_ops(op)						\
	original_security_ops.op = ops->op; smp_wmb(); ops->op = ccs_##op;


#define LEN_BUF_PATH 4200
int pos_buf_path = 0;
char buf_path[LEN_BUF_PATH + 1];



/*
 * Dummy variable for finding address of
 * "struct security_operations *security_ops".
 */
static struct security_operations *probe_dummy_security_ops;

/**
 * probe_security_file_alloc - Dummy function which does identical to security_file_alloc() in security/security.c.
 *
 * @file: Pointer to "struct file".
 *
 * Returns return value from security_file_alloc().
 */
static int probe_security_file_alloc(struct file *file)
{
	return probe_dummy_security_ops->file_alloc_security(file);
}


/**
 * probe_kernel_read - Wrapper for kernel_read().
 *
 * @file:   Pointer to "struct file".
 * @offset: Starting position.
 * @addr:   Buffer.
 * @count:  Size of @addr.
 *
 * Returns return value from kernel_read().
 */
static int __init probe_kernel_read(struct file *file, unsigned long offset,
		char *addr, unsigned long count)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 8)
	/*
	 * I can't use kernel_read() because seq_read() returns -EPIPE
	 * if &pos != &file->f_pos .
	 */
	mm_segment_t old_fs;
	unsigned long pos = file->f_pos;
	int result;
	file->f_pos = offset;
	old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_read(file, (void __user *)addr, count, &file->f_pos);
	set_fs(old_fs);
	file->f_pos = pos;
	return result;
#else
	return kernel_read(file, offset, addr, count);
#endif
}

/**
 * probe_find_symbol - Find function's address from /proc/kallsyms .
 *
 * @keyline: Function to find. This is " probe_security_file_alloc".
 *
 * Returns address of specified function on success, NULL otherwise.
 */
static void *__init probe_find_symbol(const char *keyline)
{
	printk("probe_find_symbol: [%s]\n", keyline);

	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		struct file_system_type *fstype = NULL;
		struct vfsmount *mnt = do_kern_mount("proc", 0, "proc", NULL);
#else
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = kern_mount(fstype);
#endif
		struct dentry *root;
		struct dentry *dentry;
		/*
		 * We embed put_filesystem() here because it is not exported.
		 */
		if (fstype)
			module_put(fstype->owner);
		if (IS_ERR(mnt))
			goto out;
		root = dget(mnt->mnt_root);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
		mutex_lock(&root->d_inode->i_mutex);
		dentry = lookup_one_len("kallsyms", root, 8);
		mutex_unlock(&root->d_inode->i_mutex);
#else
		down(&root->d_inode->i_sem);
		dentry = lookup_one_len("kallsyms", root, 8);
		up(&root->d_inode->i_sem);
#endif
		dput(root);
		if (IS_ERR(dentry))
			mntput(mnt);
		else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
			struct path path = { mnt, dentry };
			file = dentry_open(&path, O_RDONLY, current_cred());
#else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					, current_cred()
#endif
					);
#endif
		}
	}
	if (IS_ERR(file) || !file)
		goto out;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf) {
		int len;
		int offset = 0;
		while ((len = probe_kernel_read(file, offset, buf,
						PAGE_SIZE - 1)) > 0) {
			char *cp;
			buf[len] = '\0';
			cp = strrchr(buf, '\n');
			if (!cp)
				break;
			*(cp + 1) = '\0';
			offset += strlen(buf);
			cp = strstr(buf, keyline);
			if (!cp)
				continue;
			*cp = '\0';
			while (cp > buf && *(cp - 1) != '\n')
				cp--;
			entry = simple_strtoul(cp, NULL, 16);
			break;
		}
		kfree(buf);
	}
	filp_close(file, NULL);
out:
	return (void *) entry;
}


// function = probe_security_file_alloc,
// addr = &probe_dummy_security_ops,
// symbol = " security_file_alloc"
static void * __init probe_find_variable(void *function, unsigned long addr, const char *symbol)
{
	int i;
	u8 *base;
	u8 *cp = function;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)
	if (*symbol == ' ')
		base = probe_find_symbol(symbol);
	else
#endif
		base = __symbol_get(symbol);
	if (!base)
		return NULL;

	/* First, assume absolute adressing mode is used. */
	for (i = 0; i < 128; i++) {
		if (*(unsigned long *) cp == addr)
			return base + i; // 从这里返回
		cp++;
	}

	cp = function;
	for (i = 0; i < 128; i++) {
		if ((unsigned long) (cp + sizeof(int) + *(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp += sizeof(int) + *(int *) cp;
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
	cp = function;
	for (i = 0; i < 128; i++) {
		if ((unsigned long) (long) (*(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp = (void *) (long) (*(int *) cp);
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
	return NULL;
}

struct security_operations * __init probe_security_ops(void)
{
	struct security_operations **ptr;
	struct security_operations *ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *cp;
	/* Guess "struct security_operations *security_ops;". */
	cp = probe_find_variable(probe_security_file_alloc, (unsigned long)
			&probe_dummy_security_ops,
			" security_file_alloc\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve security_file_alloc().\n");
		return NULL;
	}
	/* This should be "struct security_operations *security_ops;". */
	ptr = *(struct security_operations ***) cp;
#else
	/* This is "struct security_operations *security_ops;". */
	ptr = (struct security_operations **) __symbol_get("security_ops");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve security_ops structure.\n");
		return NULL;
	}
	printk(KERN_INFO "security_ops=%p\n", ptr);
	ops = *ptr;
	if (!ops) {
		printk(KERN_ERR "No security_operations registered.\n");
		return NULL;
	}
	return ops;
}






void get_full_path(struct dentry *dentry)
{
	pos_buf_path = LEN_BUF_PATH;
	while (dentry->d_parent != dentry)
	{
		int len = strlen(dentry->d_name.name);
		pos_buf_path -= len;
		memcpy(buf_path + pos_buf_path, dentry->d_name.name, len);
		pos_buf_path -= 1;
		buf_path[pos_buf_path] = '/';
		dentry = dentry->d_parent;
	}
}

/**
 * ccs_inode_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */

static int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	pos_buf_path = LEN_BUF_PATH;
	get_full_path(dentry);
	printk("pid: [%d], mkdir: [%s]\n", current->pid, buf_path + pos_buf_path);
	while (!original_security_ops.inode_mkdir);
	return original_security_ops.inode_mkdir(dir, dentry, mode);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

/**
 * ccs_file_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_file_open(struct file *f, const struct cred *cred)
{
	get_full_path(f->f_path.dentry);
	printk("pid: [%d], open: [%s]\n", current->pid, buf_path + pos_buf_path);

	while (!original_security_ops.file_open);
	return original_security_ops.file_open(f, cred);
}
#else
/**
 * ccs_dentry_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_dentry_open(struct file *f, const struct cred *cred)
{
	get_full_path(f->f_path.dentry);
	printk("pid: [%d], open: [%s]\n", current->pid, buf_path + pos_buf_path);
	while (!original_security_ops.dentry_open);
	return original_security_ops.dentry_open(f, cred);
}
#endif


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]


#define NIPQUAD_FMT "%u.%u.%u.%u"


void print_socket_connect_addr(struct sockaddr *addr)
{
	struct sockaddr_in *p = (struct sockaddr_in *)addr;
	printk("sin_family: [%d], ", p->sin_family);
	printk("sin_port: [%u], ", p->sin_port);
	/* printk("sin_ip: [%s]\n", inet_ntoa(p->sin_addr)); */
	printk("ip: " NIPQUAD_FMT "\n", NIPQUAD(p->sin_addr));
}

/**
 * ccs_socket_connect - Check permission for connect().
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_socket_connect(struct socket *sock, struct sockaddr *addr,
		int addr_len)
{
	print_socket_connect_addr(addr);
	while (!original_security_ops.socket_connect);
	return original_security_ops.socket_connect(sock, addr, addr_len);
}

static void __init ccs_update_security_ops(struct security_operations *ops)
{
	swap_security_ops(inode_mkdir);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	swap_security_ops(file_open);
#else
	swap_security_ops(dentry_open);
#endif
	swap_security_ops(socket_connect);
}


static int __init ccs_init(void)
{
	buf_path[LEN_BUF_PATH] = 0;
	ops = probe_security_ops();
	if (!ops)
		goto out;
	ccs_update_security_ops(ops);
	printk(KERN_INFO "AKARI: 1.0.31   2015/01/12\n");
	printk(KERN_INFO "Access Keeping And Regulating Instrument registered.\n");
	return 0;
out:
	return -EINVAL;
}

static void __exit ccs_exit(void)
{
	ops->inode_mkdir = original_security_ops.inode_mkdir;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	ops->file_open = original_security_ops.file_open;
#else
	ops->dentry_open = original_security_ops.dentry_open;
#endif
	ops->socket_connect = original_security_ops.socket_connect;
	return;
}

module_init(ccs_init);
module_exit(ccs_exit);
MODULE_LICENSE("GPL");
