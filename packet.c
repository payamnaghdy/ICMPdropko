#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Payam Naghdi");
MODULE_DESCRIPTION("A simple module for ICMP packet drop.");
MODULE_VERSION("0.1");
struct sk_buff *sock_buff;
struct iphdr *ip_header;
unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in, const struct net_device *out,
                       int(*okfn)(struct sk_buff *));


static struct nf_hook_ops icmp_drop __read_mostly = {
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,
        .hook = (nf_hookfn *) icmp_hook
};




static int __init icmp_drop_init(void)
{


        printk(KERN_INFO "Icmp packet droper loaded\n");
       int ret = nf_register_net_hook(&init_net,&icmp_drop); /*Record in net filtering */
       if(ret)
           printk(KERN_INFO "FAILED");
       return  ret;

}

static void __exit  icmp_drop_exit(void)
{
        printk(KERN_INFO "Bye icmp drop module unloaded\n");
        nf_unregister_net_hook(&init_net,&icmp_drop); /*UnRecord in net filtering */
}


unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb,

        const struct net_device *in, const struct net_device *out,

        int(*okfn)(struct sk_buff *))

{
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        if(!sock_buff) { return NF_DROP;}
         if (ip_header->protocol==IPPROTO_ICMP) {
             printk(KERN_INFO "Got ICMP Reply packet and dropped it. \n");
             return NF_DROP;
         }
         return NF_ACCEPT;

}






module_init(icmp_drop_init);
module_exit(icmp_drop_exit);

