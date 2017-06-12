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


extern int hsl_debug_ifp(struct seq_file *m, struct hsl_avl_tree *port_tree);

int hsl_avl_traversal_debug_porttree_sum(void *data, void *user_data)
{
	struct hsl_if *ifp =NULL;	
	struct seq_file *m = NULL;
	if (data == NULL) 
		return 0;
	ifp = (struct hsl_if *)data;
	m   = (struct seq_file *)user_data;

	seq_printf(m, "ifindex:%d--name:%s\n", ifp->ifindex, ifp->name);
	seq_printf(m,"\n");
	return 0;
}

static void __debug_port_tree_sum(struct seq_file *m, struct hsl_avl_tree *port_tree)
{
	struct hsl_if tifp, *ifp;
	struct hsl_avl_node *node;

	//HSL_FN_ENTER ();

	HSL_IFMGR_LOCK;
	hsl_avl_tree_traverse(port_tree, hsl_avl_traversal_debug_porttree_sum, m);
	HSL_IFMGR_UNLOCK;
 	
}

int hsl_avl_traversal_debug_vlantree(void *data, void *user_data)
{
  struct hsl_vlan_port *v;
  struct seq_file *m = NULL;

  m = (struct seq_file *)user_data;
  if (m == NULL)
  	return 0;
  
  v = (struct hsl_vlan_port *) HSL_AVL_NODE_INFO ((struct hsl_avl_node *)data);
  if (v == NULL)
  	return 0;

  seq_printf(m, "=====================VLAN START====================================\n");
  seq_printf(m, "vlan id:%d\n", v->vid);
  __debug_port_tree_sum(m, v->port_tree);
  seq_printf(m, "=====================VLAN STOP=====================================\n\t");
  return 0;
}

static void __debug_vlan_tree(struct seq_file *m, struct hsl_avl_tree  *vlan_tree)
{
	HSL_BRIDGE_LOCK;
	hsl_avl_tree_traverse(vlan_tree, hsl_avl_traversal_debug_vlantree, m);
	HSL_BRIDGE_UNLOCK;
}



static void _debug_bridge_show(struct seq_file *m ,  struct hsl_bridge *bridge)
{
	if (bridge == NULL )
		return;
	seq_printf(m, "bridge name:%s\n", bridge->name);
	seq_printf(m, "ageing time:%d\n", bridge->ageing_time);
	seq_printf(m, "flags:%x\n", bridge->flags);
	if (bridge->port_tree != NULL)
		__debug_port_tree_sum(m, bridge->port_tree);
	if (bridge->vlan_tree != NULL)
		__debug_vlan_tree(m, bridge->vlan_tree);
}

int hsl_bridge_proc_show(struct seq_file *m, void *v)
{
	_debug_bridge_show(m, p_hsl_bridge_master->bridge);
	return 0;
}