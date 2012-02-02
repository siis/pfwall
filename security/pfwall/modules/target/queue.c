#include <net/netlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/wall.h>

/* Netlink interface definitions */

// extern struct wall_interfaces_msg_ctx *wall_violations_send_msg(char*);
// extern struct pft_table pft_filter_table;

int pft_ulog_target(struct pf_packet_context *p, void *target_specific_data)
{
	return 0;
	/*
	   {
			if (read_like(tclass, requested) && (ts_find_subject(stype, current->comm) == 0) &&
			(ts_find_ttype(stype, current->comm, ttype) == 1)) {
				verdict = do_pft_filter(p, 0, &rule);
			}
			*/
			# if 0
//			printk(KERN_INFO "wall: verdict: %d matching rule: %d\n", verdict, rule);

//			if (ts_find_tip(stype, current->comm, p->trace.entries[p->trace_first_program_ip]) == 1) // Not found; new IP //
			{
//				printk(KERN_INFO "wall: new IP: %s,%s,%lx\n", stype, current->comm, p->trace.entries[p->trace_first_program_ip]);
				char* vio_msg_str = NULL;
				struct wall_violations_msg_ctx* vio_msg = NULL;
//				rdtscl(time_strt);
				vio_msg_str = kasprintf(GFP_ATOMIC, "Violation: %lx", p->trace.entries[p->trace_first_program_ip]);
//				printk(KERN_INFO "wall: Sending message to daemon\n");
				vio_msg = wall_violations_send_msg(vio_msg_str);
				kfree(vio_msg_str);
				if (vio_msg != NULL) // Message was sent to daemon, wait for reply //
				{
					if (!in_atomic())
					{
//						while (vio_msg->state == NL_VIOLATIONS_STATE_PENDING);
						// rdtscl(time_end);
//						printk(KERN_INFO "wall: Decision came back: %lx\n", p->trace.entries[p->trace_first_program_ip]);
					}
					else
						printk(KERN_WARNING "wall: *************************** ATOMIC **********************\n");
					kfree(vio_msg);
				}

//				schedule();
				// ts_add_tip(stype, current->comm, p->trace.entries[p->trace_first_program_ip]);

			}
			// Invoke process firewall

			// Match incoming "packet" against firewall rules, and take specified action //
//			if (stack_str)
//				kfree(stack_str);
//			if (log_str)
//				kfree(log_str);
		}
	}
	# endif
}

static int __init pf_ulog_target_init(void)
{
	int rc = 0;
	struct pft_target_module ulog_target_module = {
		.list = {NULL, NULL},
		.name = "ulog",
//		.context_mask = PF_CONTEXT_TYPE | PF_CONTEXT_INTERFACE |
//			PF_CONTEXT_FILENAME | PF_CONTEXT_VM_AREA_STRINGS,
		/* TODO: The context needed to log is provided
			as arguments to the target module, in
			this case, only PF_CONTEXT_TYPE (default
			context) is required in all cases.  */
		.target = &pft_ulog_target
	};

	printk(KERN_INFO PFWALL_PFX "initializing ulog target module\n");
	rc = pf_register_target(&ulog_target_module);
	if (rc < 0) {
		printk(KERN_INFO PFWALL_PFX "error registering target module ulog: %d", rc);
	}

	/* Netlink socket initialization
	my_nl_sock = netlink_kernel_create(&init_net, NETLINK_WALL_VIOLATIONS, 0,
		my_nl_rcv_msg, NULL, THIS_MODULE);
	if (!my_nl_sock) {
		printk(KERN_ERR "%s: receive handler registration failed\n", __func__);
		return -ENOMEM;
	}
	*/

    return 0;
	return rc;
}
module_init(pf_ulog_target_init);

#if defined(CONFIG_NET)
static struct sock *my_nl_sock;
#endif
extern struct net init_net;

u32 violations_daemon_pid;
// EXPORT_SYMBOL(violations_daemon_pid);
DEFINE_MUTEX(my_mutex);

/*
static int
my_load_notify(struct notifier_block *this, unsigned long event, void *ptr)
{
	printk(KERN_WARNING "In notifier_callback: %lu\n", event);
}
*/
/*
int violations_daemon_send_msg(char* msg)
{
	struct sk_buff* skb;
	struct nlmsghdr* nlh;
	int rc = 0;
	int type = NL_VIOLATIONS_TYPE_REQUEST_DECISION;
	int len = strlen(msg) + 1;
	if (violations_daemon_pid == -1)
		return NL_VIOLATIONS_RESPONSE_ALLOW;
	skb = alloc_skb(NLMSG_SPACE(len), GFP_ATOMIC);

// 	if (!skb)
//		goto oom;

	// Set nlmsghdr fields //
	// nlh = NLMSG_PUT(skb, violations_daemon_pid, );
}
*/

/* Send a netlink packet to userspace
 * @message - String of message to be sent - maximum size of message must be 1023
 * Message is sent to violations_daemon_pid
 * Returns a reference to a context structure which indicates ready when
 * ctx->state == NL_VIOLATIONS_STATE_FINISHED
 * If no daemon is registered, or other error, returns NULL
 */

struct wall_violations_msg_ctx* wall_violations_send_msg(char* message)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int rc = 0;

	struct wall_violations_msg_ctx* vio_msg = kzalloc(GFP_ATOMIC, sizeof(struct wall_violations_msg_ctx));

	if (violations_daemon_pid == 0) /* None registered */
		goto out;

	vio_msg->state = NL_VIOLATIONS_STATE_PENDING;
	vio_msg->msg.index = (unsigned int) vio_msg;
	vio_msg->pid = task_pid_nr(current);
	strncpy(vio_msg->msg.payload.request, message, strlen(message) + 1);

	/* Allocate space for skb - header + data + 100 for tail */
	skb = alloc_skb(NLMSG_SPACE(sizeof(struct nlmsghdr) + sizeof(struct wall_violations_msg) + 100) , GFP_ATOMIC);

	if (!skb)
		goto oom;

	/* Fill up skb header with nlmsghdr */
	nlh = nlmsg_put(skb, violations_daemon_pid, 4444, NL_VIOLATIONS_TYPE_REQUEST_DECISION, sizeof(struct wall_violations_msg), 0);

	/* Copy the data */
	memcpy(NLMSG_DATA(nlh), &(vio_msg->msg), sizeof(struct wall_violations_msg));

	/* Send the netlink packet to userspace */

	rc = netlink_unicast(my_nl_sock, skb, violations_daemon_pid, MSG_DONTWAIT);
	if (rc < 0) {
		printk(KERN_INFO "wall: failed to send msg to userspace\n");
		goto out;
	}

	return vio_msg;
out:
	if (skb)
		kfree(skb);
	kfree(vio_msg);
	return NULL;

// nlmsg_failure:
//	kfree_skb(skb);

oom:
	printk(KERN_INFO "wall: Out of memory: %d:%s\n", __LINE__, __FUNCTION__);
	goto out;

}
EXPORT_SYMBOL(wall_violations_send_msg);

#if 0
static int
my_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int type;

    skb_get(skb);
    type = nlh->nlmsg_type;
	if (type == NL_VIOLATIONS_TYPE_REGISTER_DAEMON)
	{
		violations_daemon_pid = NETLINK_CREDS(skb)->pid;
		printk(KERN_INFO "wall: registered violations daemon: %u", violations_daemon_pid);
		// struct wall_violations_msg_ctx* vio_msg = wall_violations_send_msg("This is a test violation");
		return 0;
	}
	else if (type == NL_VIOLATIONS_TYPE_REQUEST_RESPONSE)
	{

		struct wall_violations_msg_ctx* response = (struct wall_violations_msg_ctx*) ((struct wall_violations_msg*) NLMSG_DATA(nlh))->index;
		printk(KERN_INFO "response: %d\n", response->pid);
		response->state = NL_VIOLATIONS_STATE_FINISHED;
	}
    return 0;
}
static void
my_nl_rcv_msg(struct sk_buff *skb)
{
printk(KERN_ALERT "wall: got a msg from userspace\n");
    mutex_lock(&my_mutex);
    my_rcv_msg(skb, nlmsg_hdr(skb));
   mutex_unlock(&my_mutex);
}
#endif

# if 0
static int
my_init(void)
{
}

static void
my_exit(void)
{
    if (my_nl_sock) {
	netlink_kernel_release(my_nl_sock);
    }
}
#endif
