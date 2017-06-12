#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "config.h"
#include "hal_types.h"
#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_ifmgr.h"
#include "hsl_avl.h"
#include "hal_l2.h"
#include "hsl_bridge.h"




static void _debug_hsl_ifIP(struct seq_file *m, hsl_ifIP_t *ip)
{
	seq_printf(m, "-------hsl_ifIP_t start------------\n");
	
	seq_printf(m, "mac:%pM\n", ip->mac);
	seq_printf(m, "vid:%d\n", ip->vid);
	seq_printf(m, "arpTimeout:%d\n", ip->arpTimeout);
	seq_printf(m, "mtu:%d\n", ip->mtu);
	seq_printf(m,"--------hsl_ifIP_t end--------------\n");
}


static void _debug_hsl_ifL2_ethernet(struct seq_file *m, hsl_ifL2_ethernet_t *l2_ethernet)
{
	seq_printf(m, "-------hsl_ifL2_ethernet_t start------------\n");
	seq_printf(m, "ifindex:%d\n", l2_ethernet->ifindex);
	seq_printf(m, "speed:%lld\n", l2_ethernet->speed);
	seq_printf(m, "mtu:%d\n", l2_ethernet->mtu);
	seq_printf(m, "duplex:%d\n", l2_ethernet->duplex);
	seq_printf(m, "autonego:%d\n", l2_ethernet->autonego);
	seq_printf(m, "bandwidth:%lld\n", l2_ethernet->bandwidth);
	seq_printf(m, "mac:%pM\n", l2_ethernet->mac);
	if (l2_ethernet->port != NULL && l2_ethernet->port->bridge != NULL) {
		seq_printf(m, "bind bridge:%s\n", l2_ethernet->port->bridge->name);
	} else {
		seq_printf(m, "bind bridge failed!\n");
	}
	seq_printf(m, "-------hsl_ifL2_ethernet_t end------------\n");
}

static int debug_ifmgr_uuu(struct seq_file *m, struct hsl_if *ifp)
{
	switch (ifp->type)
	{
		case HSL_IF_TYPE_UNK:
			break;
		case HSL_IF_TYPE_LOOPBACK:
			break;
		case HSL_IF_TYPE_IP:
			_debug_hsl_ifIP(m, &ifp->u.ip);
			break;
		case HSL_IF_TYPE_L2_ETHERNET:
			_debug_hsl_ifL2_ethernet(m, &ifp->u.l2_ethernet);
			break;
		case HSL_IF_TYPE_MPLS:
			break;
		default:
			break;
	}
}

int hsl_avl_traversal_debug_iftree(void *data, void *user_data)
{
	struct hsl_if *ifp =NULL;	
	struct seq_file *m = NULL;
	if (data == NULL) 
		return 0;
	ifp = (struct hsl_if *)data;
	m   = (struct seq_file *)user_data;
	seq_printf(m, "===============================================\n");
	seq_printf(m, "ifindex:%d\n", ifp->ifindex);
	seq_printf(m, "is_agg_member:%d\n", ifp->is_agg_member);
	seq_printf(m, "type:%#x\n", ifp->type);
	seq_printf(m, "val(hold counter):%d\n", ifp->val.counter);
	seq_printf(m, "interfaece name:%s\n", ifp->name);
	seq_printf(m, "mapped name:%s\n", ifp->mapped_name);
	seq_printf(m, "operCnt:%d\n", ifp->operCnt);
	seq_printf(m, "flags:%#x\n", ifp->flags);
	seq_printf(m, "if_flags:%#x\n", ifp->if_flags);
	seq_printf(m, "pkt_flags:%d\n", ifp->pkt_flags);
	seq_printf(m, "if_property:%#x\n", ifp->if_property);
	seq_printf(m, "ngn_type_enableed:%d\n", ifp->ngn_type_enabled);
	seq_printf(m, "ngn_type:%#x\n", ifp->ngn_type);
	debug_ifmgr_uuu(m, ifp);
	seq_printf(m, "================================================\n\r");
	return 0;
}

int hsl_debug_ifp(struct seq_file *m, struct hsl_avl_tree *port_tree)
{
  struct hsl_if tifp, *ifp;
  struct hsl_avl_node *node;

  //HSL_FN_ENTER ();

  HSL_IFMGR_LOCK;
  hsl_avl_tree_traverse(port_tree, hsl_avl_traversal_debug_iftree, m);
  HSL_IFMGR_UNLOCK;
  return 0; 
}
int hsl_ifmgr_proc_show(struct seq_file *m, void *v)
{
	hsl_debug_ifp(m, p_hsl_if_db->if_tree);
	return 0;
}