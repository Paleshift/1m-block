#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string.h>

//+++++
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>

#include <sys/sysinfo.h>
//+++++

//+++++
clock_t elapsed;
float   sec;
#define START_TIME \
{\
    elapsed = -clock();\
}
#define STOP_TIME \
{\
    elapsed += clock();\
	sec = (float)elapsed/CLOCKS_PER_SEC;\
}
#define PRINT_TIME(str) \
{\
    printf("\n[%-23s: %2.5f s]\n\n",str,sec);\
}
//+++++
//For measuring execution time

typedef struct {
	#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
	#  endif

	#  if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
    uint8_t ihl:4;
	#  endif
    //uint8_t version_and_ihl;

    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t s_addr;
    uint32_t d_addr;
} IpHdr;
//Define IPv4 header struct

typedef struct{
    u_int16_t s_port;
    u_int16_t d_port;
    u_int32_t seq_num;
    u_int32_t ack_num;

#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t reserved:4;
    u_int8_t offset:4;
#  endif

#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t offset:4;
    u_int8_t reserved:4;
#  endif

    u_int8_t flags;
#  define FIN  0x01
#  define SYN  0x02
#  define RST  0x04
#  define PUSH 0x08
#  define ACK  0x10
#  define URG  0x20

    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
} TcpHdr;
//Define TCP header struct

char number;
//char **hostname;

//+++++
std::set<std::string> test;
//Define the set 'test' that stores strings(Not overlapped each other)
//from specific source (Ex. top-1m.csv) by using "std::set"
//+++++

//Define two global variables to store the parameters of main()

//+++++
char *strnstr(const char *source, const char *to_find, int range) {

	int to_find_length = strlen(to_find);

	if (to_find_length == 0){
		return (char *)source;
	}

	char *temp_arr = (char *)malloc(range + 1);

	strncpy(temp_arr, source, range);
	temp_arr[range] = '\0';

	char *result = strstr(temp_arr, to_find);

	free(temp_arr);

	return result;
}
//+++++
//Define "strnstr"

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		/*printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);*/
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		/*printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);*/
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		//printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		//printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		//printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		//printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		//printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		//printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		//printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		//printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		/*printf("\n");
		dump(data, ret);

		printf("payload_len=%d ", ret);*/
	}

	//fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);
	//printf("entering callback..\n\n");
	
	unsigned char *pkt_data;
	int temp;
	
	temp = nfq_get_payload(nfa, &pkt_data);

	char *sitename = NULL;

	IpHdr *iphdr = (IpHdr *)pkt_data;
	//Parsing IP

	if (iphdr->protocol != 0x06) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	//If Protocol in IPv4 header is not a TCP(0x06), ACCEPT it. 
	
	TcpHdr *tcphdr = (TcpHdr *)(pkt_data + iphdr->ihl * 4);
	//Parsing TCP
	const char *httphdr = (const char *)((pkt_data + iphdr->ihl * 4) + (tcphdr->offset * 4));
	//Parsing HTTP ("unsigned char" -> "const char")
	
	if ((ntohs(tcphdr->d_port) == 80) && (strncmp(httphdr, "GET", 3) == 0) && ((sitename = strnstr(httphdr, "Host: ", 100)) != NULL)) {
		//ntohs(tcphdr->d_port) == 80 -> Check whether http://~~ or not
		//strncmp(httphdr, "GET", 3) == 0 -> Check whether Request Method is GET or not
		//(sitename = strnstr(httphdr, "Host: ", 50)) != NULL -> Check whether Host: ~~ or not in range(Length: 50)
		
		/*for (int i = 1; i < number; i++) {
			if (strncmp(sitename + 6, hostname[i], strlen(hostname[i])) == 0) {
				//sitename + 6 -> H(1) o(2) s(3) t(4) :(5)  (6)
				printf("Bad site No.%d(%s) is blocked!\n\n\n", i, hostname[i]);

				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		}*/

		START_TIME;

		std::string pkt_site_string(sitename + 6);
		std::istringstream source_string(pkt_site_string);
		getline(source_string, pkt_site_string, '\r');

		if(test.find(pkt_site_string) != test.end()){
			printf("\n\nBad site (%s) is blocked!", pkt_site_string.c_str());

			STOP_TIME;
			PRINT_TIME("Examining time");
			
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}

		STOP_TIME;
		PRINT_TIME("Examining time");
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

//+++++
void print_sysinfo(struct sysinfo *sys, unsigned long *ram){
	
	printf("\n");
	printf("Uptime               : %ld\n", sys->uptime);
	printf("Total RAM            : %lu\n", sys->totalram);
	printf("Free RAM             : %lu\n", sys->freeram);
	printf("Shared RAM           : %lu\n", sys->sharedram);
	printf("Buffer RAM           : %lu\n", sys->bufferram);
	printf("Total swap           : %lu\n", sys->totalswap);
	printf("Free swap            : %lu\n", sys->freeswap);
	printf("The number of process: %u\n", sys->procs);
	printf("\n");

	*ram = sys->totalram - sys->freeram;
}
//+++++

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	//+++++
	struct sysinfo sys_info;
	unsigned long unloaded_ram, loaded_ram;
	//+++++

	//+++++
	printf("[Sysinfo before loading]\n");
	sysinfo(&sys_info);
	print_sysinfo(&sys_info, &unloaded_ram);
	//+++++

	if (argc < 2) {
		//printf("syntax : netfilter-test <host>\n");
		printf("syntax : 1m-block <site list file>\n");
		//printf("sample : netfilter-test test.gilgil.net\n");
		printf("sample : 1m-block top-1m.txt\n");

		return 0;
	}

	number = argc;
	//Update global variable ("number") by parameter of main().

	//+++++
	START_TIME;

	std::fstream fp;
	fp.open(argv[1], std::ios::in);

	if (!fp) {
		printf("There is no %s..\n", argv[1]);

		return 0;
	}

	while(!fp.eof()){
		std::string index_line, name_line;

		std::getline(fp, index_line, ',');
		std::getline(fp, name_line, '\n');

		test.insert(name_line);
		//Update global variable ("test") by parameter of main().
	}

	fp.close();

	printf("\nTest file (%ld) is loaded!\n", test.size());

	STOP_TIME;
	PRINT_TIME("Getting and inserting time");


	printf("\n[Sysinfo after loading]\n");
	sysinfo(&sys_info);
	print_sysinfo(&sys_info, &loaded_ram);

	printf("\nUsed RAM for loading test file: %lu\n\n", loaded_ram - unloaded_ram);
	printf("\n");
	//+++++

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets..\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received!\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}