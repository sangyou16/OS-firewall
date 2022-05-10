#include <linux/init.h> 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <asm/uaccess.h>

#define NIPQUAD(address) \
	((unsigned char *)&address)[0], \
	((unsigned char *)&address)[1], \
	((unsigned char *)&address)[2], \
	((unsigned char *)&address)[3]
    
#define FORWARD_PORT 7777
#define DROP_PORT 3333

#define PROC_DIRNAME "myproc"
#define PROC_HOOK_FILENAME "myproc"


static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file_hook;

unsigned short port_for_forward = 0;
unsigned short port_for_drop = 0;

static int my_open(struct inode *inode, struct file *file){
    return 0;
}
static ssize_t my_read(struct file *file, char __user *user_buffer, size_t count, loff_t *ppos){
    return 0;
}
static ssize_t my_write (struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos){
    char input[20];
    printk("Before writing port\n");
    copy_from_user(input, user_buffer, count); 
    printk("Done writing port \n");
    sscanf(input, "%hd %hd", &port_for_drop, &port_for_forward);
    return count;
}

static const struct file_operations myproc_fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .read = my_read,
    .write = my_write,
};

static unsigned int hookFunc_PRE_ROUTING(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *ipHeader;
    struct tcphdr *tcpHeader;
    
    if(!skb)
        return NF_ACCEPT;
    
    ipHeader = ip_hdr(skb);
    tcpHeader = tcp_hdr(skb); 

    printk("PRE_ROUTING  packet (%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest), NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr)); //initial

    if ( ntohs(tcpHeader->source) == port_for_forward){
        ((unsigned char *)&ipHeader->daddr)[0] = 10; ((unsigned char *)&ipHeader->daddr)[1] = 0;
        ((unsigned char *)&ipHeader->daddr)[2] = 2;  ((unsigned char *)&ipHeader->daddr)[3] = 15;     
        printk("Forwarding: PRE_ROUTING(%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest),NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr));         
        tcpHeader->source = htons(FORWARD_PORT);
        tcpHeader->dest = htons(FORWARD_PORT);
        ((unsigned char *)&ipHeader->daddr)[0] = 130; ((unsigned char *)&ipHeader->daddr)[1] = 12;
        ((unsigned char *)&ipHeader->daddr)[2] = 7;  ((unsigned char *)&ipHeader->daddr)[3] = 2;   
        printk("Forwarding: PRE_ROUTING(%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest), NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr)); //after the changing of port
        return NF_ACCEPT;
    } else if(ntohs(tcpHeader->source) == port_for_drop ){
        printk("Drop: PRE_ROUTING(%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest), NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr)); //claiming this is the drop packet
        tcpHeader->source = htons(DROP_PORT);
        tcpHeader->dest = htons(DROP_PORT); 
        ipHeader = ip_hdr(skb);
        tcpHeader = tcp_hdr(skb); 
        printk("Drop: PRE_ROUTING(%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest), NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr)); //after changing of port 
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static unsigned int hookFunc_LOCAL_IN(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct tcphdr *tcpHeader;
    tcpHeader = tcp_hdr(skb); 
	if (!skb)
		return NF_ACCEPT;    

    if((ntohs(tcpHeader->source)==DROP_PORT)&&(ntohs(tcpHeader->dest)==DROP_PORT)) { //check whether it has been properly dropped. if this is not shown then its been dropped successfully.
    struct iphdr *ipHeader;
    ipHeader = ip_hdr(skb);
    ((unsigned char *)&ipHeader->daddr)[0] = 10; ((unsigned char *)&ipHeader->daddr)[1] = 0;
    ((unsigned char *)&ipHeader->daddr)[2] = 2;  ((unsigned char *)&ipHeader->daddr)[3] = 15;   
    printk("Dropped: LOCAL_IN(%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest), NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr)); 
   }

    return NF_ACCEPT;
}

static unsigned int hookFunc_FORWARD(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct tcphdr *tcpHeader;
    tcpHeader = tcp_hdr(skb); 

    if((ntohs(tcpHeader->source)== FORWARD_PORT)&&(ntohs(tcpHeader->dest)== FORWARD_PORT)) {
    struct iphdr *ipHeader;
    ipHeader = ip_hdr(skb);
    ((unsigned char *)&ipHeader->daddr)[0] = 130; ((unsigned char *)&ipHeader->daddr)[1] = 12;
    ((unsigned char *)&ipHeader->daddr)[2] = 7;  ((unsigned char *)&ipHeader->daddr)[3] = 2;   
    //changed destination IP address for FORWARDING packet
 
    printk("Forwarding: FORWARD(%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest),NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr)); 
    }
        
    return NF_ACCEPT;
}

static unsigned int hookFunc_POST_ROUTING(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    
    struct tcphdr *tcpHeader;
    tcpHeader = tcp_hdr(skb); 
    
    if((ntohs(tcpHeader->source)== FORWARD_PORT)&&(ntohs(tcpHeader->dest)== FORWARD_PORT)) {
    struct iphdr *ipHeader;
    ipHeader = ip_hdr(skb);
    ((unsigned char *)&ipHeader->daddr)[0] = 130; ((unsigned char *)&ipHeader->daddr)[1] = 12;
    ((unsigned char *)&ipHeader->daddr)[2] = 7;  ((unsigned char *)&ipHeader->daddr)[3] = 2;
    //changed destination IP address for POST_ROUTING    
    printk("Forwarding: POST_ROUTING(%d;%5d;%5d;%d.%d.%d.%d;%d.%d.%d.%d)\n", skb->protocol ,ntohs(tcpHeader->source), ntohs(tcpHeader->dest), NIPQUAD(ipHeader -> saddr), NIPQUAD(ipHeader -> daddr)); 
     }
    return NF_ACCEPT;
}

static struct nf_hook_ops my_nf_ops_hook_PRE_ROUTING = {

    .hook = hookFunc_PRE_ROUTING,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,    
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops my_nf_ops_hook_LOCAL_IN = {
    .hook = hookFunc_LOCAL_IN,
    .hooknum = NF_INET_LOCAL_IN,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops my_nf_ops_hook_FORWARDING = {

    .hook = hookFunc_FORWARD,
    .hooknum = NF_INET_FORWARD,
    .pf = PF_INET,    
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops my_nf_ops_hook_POST_ROUTING = {

    .hook = hookFunc_POST_ROUTING,
    .hooknum = NF_INET_POST_ROUTING,
    .pf = PF_INET,    
    .priority = NF_IP_PRI_FIRST
};


static int __init simple_init(void){

    printk(KERN_INFO "Simple Module init\n");
   
    proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
    proc_file_hook = proc_create(PROC_HOOK_FILENAME, 0600, proc_dir, &myproc_fops);
    nf_register_net_hook(&init_net, &my_nf_ops_hook_PRE_ROUTING);
    nf_register_net_hook(&init_net, &my_nf_ops_hook_LOCAL_IN);
    nf_register_net_hook(&init_net, &my_nf_ops_hook_FORWARDING);
    nf_register_net_hook(&init_net, &my_nf_ops_hook_POST_ROUTING);

    return 0;
}

static void __exit simple_exit(void){
    
    remove_proc_entry(PROC_HOOK_FILENAME, proc_dir);
    remove_proc_entry(PROC_DIRNAME, NULL);
    nf_unregister_net_hook(&init_net, &my_nf_ops_hook_PRE_ROUTING);
    nf_unregister_net_hook(&init_net, &my_nf_ops_hook_LOCAL_IN);
    nf_unregister_net_hook(&init_net, &my_nf_ops_hook_FORWARDING);
    nf_unregister_net_hook(&init_net, &my_nf_ops_hook_POST_ROUTING);

    printk(KERN_INFO "Simple Module Exit\n");
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("Sang You Park");
MODULE_DESCRIPTION("SP3");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");