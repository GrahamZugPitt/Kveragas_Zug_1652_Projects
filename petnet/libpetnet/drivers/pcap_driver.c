/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <unistd.h>
#include <stdint.h>

#include <libnet.h>
#include <pcap.h>


#include <sys/poll.h>
#include "netinet/if_ether.h"

#include "pet_driver.h"

#include <packet_pool.h>
#include <packet.h>

//
// Define this to be nonzero if you're using libnet 1.1 instead of 1.0
//
#define LIBNET11 1

struct pcap_driver {
	char     * device_name;
	libnet_t * net_interface;
	pcap_t   * pcap_interface;
};




static int
__rx(void * driver_data)
{
	struct pcap_driver * driver_state = (struct pcap_driver *)driver_data;
	struct 
	struct pcap_pkthdr header;

	packet = pcap_next(driver_state->pcap_interface, &header);

	if (packet == NULL) {
		log_error("pcap_next returned a null pointer\n");
		exit(-1);
	}

	return 0;
}


static int
__tx(void * driver_data)
{
	struct pcap_driver * driver_state = (struct pcap_driver *)driver_data;

	int ret = 0;



//	ret = libnet_adv_write_link(driver_state->net_interface, pkt->data, pkt->size);


	if (ret < 0) {
		log_error("Can't write output packet to link\n");
		return -1;
	}

	return 0;
}


static int 
__poll(void * driver_data)
{
	return 0;
}

struct petnet_driver_ops driver_ops = {
	.poll = __poll,
	.tx   = __tx,
	.rx   = __rx
};

static int
__init()
{
	char pcap_program[10240];	// some arbitrary large number

	/* Error message buffers */
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	char net_errbuf[LIBNET_ERRORBUF_SIZE];

	struct bpf_program pcap_filter;
	bpf_u_int32		   pcap_net;
	bpf_u_int32		   pcap_mask;
	int				   pcap_fd = 0;

	// get configuration
	char * ip	 = getenv("MINET_IPADDR");
	char * device = getenv("MINET_ETHERNETDEVICE");

	if (!device) {
		cerr << "Please set MINET_ETHERNETDEVICE\n";
		exit(-1);
	}

	if (!ip) {
		cerr << "Set MINET_IPADDR" << endl;
		exit(-1);
	}

	// establish libnet session
	net_interface = libnet_init(LIBNET_LINK_ADV, device, net_errbuf);


	if (net_interface == NULL) {
		log_error("Can't open interface: %s\n", net_errbuf);
		return -1;
	}

	// establish pcap filter
	if (pcap_lookupnet(device, &pcap_net, &pcap_mask, pcap_errbuf)) {
		cerr << "Can't get net and mask for " << device << ": " << pcap_errbuf << endl;
		exit(-1);
	}

	cerr << "pcap_net=" << pcap_net << ", pcap_mask=" << pcap_mask << endl;

	if ((pcap_interface = pcap_open_live(device, 1518, 1, 0, pcap_errbuf)) == NULL) {
		cerr << "Can't open " << device << ":" << pcap_errbuf << endl;
		exit(-1);
	}


	//
	// This is crucial.  It controls what your students will see
	//
	sprintf(pcap_program, "host %s or arp", ip);

	cerr << "pcap_program='" << pcap_program << "'" << endl;

	if (pcap_compile(pcap_interface, &pcap_filter, pcap_program, 0, pcap_mask)) {
		cerr << "Can't compile filter\n";
		exit(-1);
	}

	if (pcap_setfilter(pcap_interface, &pcap_filter)) {
		cerr << "Can't set filter\n";
		exit(-1);
	}

	pcap_fd = pcap_fileno(pcap_interface);

	// connect to the ethernet mux
	MinetInit(MINET_DEVICE_DRIVER);

	ethermux_handle = (MinetIsModuleInConfig(MINET_ETHERNET_MUX) ?
						   MinetAccept(MINET_ETHERNET_MUX) :
						   MINET_NOHANDLE);

	// register pcap as an external connection
	pcap_handle = MinetAddExternalConnection(pcap_fd, pcap_fd);

	return 0;
}

