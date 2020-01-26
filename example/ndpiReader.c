#include <pcap.h>
/*client paramters*/
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */

/* Detection parameters */
static time_t capture_for = 0;
static time_t capture_until = 0;
static u_int8_t live_capture = 0;
static u_int8_t num_threads = 1;
static pcap_t * openPcapFileOrDevice(u_int16_t thread_id, const u_char * pcap_file) 
{
    u_int snaplen = 1536;
    int promisc = 1;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t * pcap_handle = NULL;
    // ocap_file is the device that we want to listen to
    // snaplen is an integer which defines the maximum number of bytes to be captured by pcap.
    // promisc, when set to true, brings the interface into promiscuous mode (however, even if it is set to false, it is possible under specific cases for the interface to be in promiscuous mode, anyway).
    // 500 is the read time out in milliseconds (a value of 0 means no time out; on at least some platforms, this means that you may wait until a sufficient number of packets arrive before seeing any packets, so you should use a non-zero timeout).
    // Lastly, pcap_error_buffer is a string we can store any error messages within.
    // The function returns our session handler. 
    if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen,
				   promisc, 500, pcap_error_buffer)) == NULL) {
        capture_for = capture_until = 0;

        live_capture = 0;
        num_threads = 1; /* Open pcap files in single threads mode */

        /* trying to open a pcap file */
        if((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL) {
            char filename[256] = { 0 };
}
void test_lib() {
    struct timeval end;
    u_int64_t processing_time_usec, setup_time_usec;
    long thread_id;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        pcap_t *cap;    
    cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
        setupDetection(thread_id, cap);
    // /* trying to open a live interface */
    // #ifdef USE_DPDK
    //   struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
    // 							  MBUF_CACHE_SIZE, 0,
    // 							  RTE_MBUF_DEFAULT_BUF_SIZE,
    // 							  rte_socket_id());

    //   if(mbuf_pool == NULL)
    //     rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: are hugepages ok?\n");

    //   if(dpdk_port_init(dpdk_port_id, mbuf_pool) != 0)
    //     rte_exit(EXIT_FAILURE, "DPDK: Cannot init port %u: please see README.dpdk\n", dpdk_port_id);
    // #else

  }