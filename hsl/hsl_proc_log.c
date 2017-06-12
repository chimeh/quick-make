#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/*
seq_printf--format
* This function follows C99 vsnprintf, but has some extensions:
 * %pS output the name of a text symbol with offset
 * %ps output the name of a text symbol without offset
 * %pF output the name of a function pointer with its offset
 * %pf output the name of a function pointer without its offset
 * %pB output the name of a backtrace symbol with its offset
 * %pR output the address range in a struct resource with decoded flags
 * %pr output the address range in a struct resource with raw flags
 * %pM output a 6-byte MAC address with colons
 * %pMR output a 6-byte MAC address with colons in reversed order
 * %pMF output a 6-byte MAC address with dashes
 * %pm output a 6-byte MAC address without colons
 * %pmR output a 6-byte MAC address without colons in reversed order
 * %pI4 print an IPv4 address without leading zeros
 * %pi4 print an IPv4 address with leading zeros
 * %pI6 print an IPv6 address with colons
 * %pi6 print an IPv6 address without colons
 * %pI6c print an IPv6 address as specified by RFC 5952
 * %pIS depending on sa_family of 'struct sockaddr *' print IPv4/IPv6 address
 * %piS depending on sa_family of 'struct sockaddr *' print IPv4/IPv6 address
 * %pU[bBlL] print a UUID/GUID in big or little endian using lower or upper
 *   case.
 * %*ph[CDN] a variable-length hex string with a separator (supports up to 64
 *           bytes of the input)
 * %n is ignored
 *
 */

static int hsl_fdb_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "proc mac is ....\n");
	return 0;
}

static int hsl_fdb_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hsl_fdb_proc_show, NULL);
}

static const struct file_operations hsl_fdb_fops = {
	.owner   = THIS_MODULE,
	.open    = hsl_fdb_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

#define ____IFMGR______START____
extern int hsl_ifmgr_proc_show(struct seq_file *m, void *v);
static int hsl_ifmgr_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hsl_ifmgr_proc_show, NULL);
}

static const struct file_operations hsl_ifmgr_fops = {
	.owner   = THIS_MODULE,
	.open    = hsl_ifmgr_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
#define ____IFMGR______STOP____

#define ____BRIDGE______START____
extern int hsl_bridge_proc_show(struct seq_file *m, void *v);
static int hsl_bridge_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hsl_bridge_proc_show, NULL);
}

static const struct file_operations hsl_bridge_fops = {
	.owner   = THIS_MODULE,
	.open    = hsl_bridge_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
#define ____BRIDGE______STOP____


int hsl_proc_log_init(void)
{
	if (!proc_mkdir("hsl", NULL)) {
		printk("proc_mkdir hsl error\n");
		return -1;
	}
	
	if (!proc_create("hsl/fdb", 0, NULL, &hsl_fdb_fops))
	{
		printk("proc_create hsl/mac failed!\n");
		return -1;
	}

	if (!proc_create("hsl/ifmrg", 0, NULL, &hsl_ifmgr_fops))
	{
		printk("proc_reate hsl/ifmrg failed!\n");
		return -1;
	}

	if (!proc_create("hsl/bridge", 0, NULL, &hsl_bridge_fops))
	{
		printk("proc_create hsl/bridge failed!\n");
		return -1;
	}
	return 0 ;
}

void hsl_proc_log_deinit(void)
{
}
