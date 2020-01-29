#include "ndpi_main.h"
#include <pcap.h>
#include <signal.h>
/*client paramters*/
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
static char * bpfFilter             = NULL; /**< bpf filter  */
static u_int8_t shutdown_app = 0, quiet_mode = 0;

/* Detection parameters */
static time_t capture_for = 0;
static time_t capture_until = 0;
static u_int8_t live_capture = 0;
static u_int8_t num_threads = 1;
/**
 * @brief Sigproc is executed for each packet in the pcap file
 */
void sigproc(int sig) {

  static int called = 0;
  int thread_id;

  if(called) return; else called = 1;
  shutdown_app = 1;

  for(thread_id=0; thread_id<num_threads; thread_id++)
    breakPcapLoop(thread_id);
}
/**
 * @brief Configure the pcap handle
 */
static void configurePcapHandle(pcap_t * pcap_handle) {

  if(bpfFilter != NULL) {
    struct bpf_program fcode;
    // Before applying our filter, we must "compile" it. The filter expression is kept in a regular string (char array).
    // The syntax is documented quite well in the man page for tcpdump;
    // I leave you to read it on your own. However, we will use simple test expressions, so perhaps you are sharp enough to figure it out from my examples.
    // The first argument is our session handle (pcap_t *handle in our previous example).
    // Following that is a reference to the place we will store the compiled version of our filter.
    // Then comes the expression itself, in regular string format.
    // Next is an integer that decides if the expression should be "optimized" or not (0 is false, 1 is true. Standard stuff.)
    // Finally, we must specify the network mask of the network the filter applies to.
    // The function returns -1 on failure; all other values imply success. 
    if(pcap_compile(pcap_handle, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
    } else {
    //   The first argument is our session handler, the second is a reference to the compiled version of the expression (presumably the same variable as the second argument to pcap_compile()).
      if(pcap_setfilter(pcap_handle, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(pcap_handle));
      } else
	printf("Successfully set BPF filter to '%s'\n", bpfFilter);
    }
  }
}
/**
 * a normal member taking two arguments and returning an integer value.
 * @param thread_id an integer argument.
 * @param filename a constant character pointer.
 * @param filename_len
 * @return The test results
 */
static int getNextPcapFileFromPlaylist(u_int16_t thread_id, char filename[], u_int32_t filename_len)
{
  if(playlist_fp[thread_id] == NULL) {
    if((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
      return -1;
  }

next_line:
  if(fgets(filename, filename_len, playlist_fp[thread_id])) {
    int l = strlen(filename);
    if(filename[0] == '\0' || filename[0] == '#') goto next_line;
    if(filename[l-1] == '\n') filename[l-1] = '\0';
    return 0;
  } else {
    fclose(playlist_fp[thread_id]);
    playlist_fp[thread_id] = NULL;
    return -1;
  }
}
static pcap_t * openPcapFileOrDevice(u_int16_t thread_id, const u_char * pcap_file) 
{
    u_int snaplen = 1536;
    int promisc = 1;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t * pcap_handle = NULL;

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

    // pcap_file is the device that we want to listen to
    // snaplen is an integer which defines the maximum number of bytes to be captured by pcap.
    // promisc, when set to true, brings the interface into promiscuous mode (however, even if it is set to false, it is possible under specific cases for the interface to be in promiscuous mode, anyway).
    // 500 is the read time out in milliseconds (a value of 0 means no time out; on at least some platforms, this means that you may wait until a sufficient number of packets arrive before seeing any packets, so you should use a non-zero timeout).
    // Lastly, pcap_error_buffer is a string we can store any error messages within.
    // The function returns our session handler. 
    if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen,
				   promisc, 500, pcap_error_buffer)) == NULL)
    {
        capture_for = capture_until = 0;

        live_capture = 0;
        num_threads = 1; /* Open pcap files in single threads mode */

        /* trying to open a pcap file */
        if((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL)
        {
            char filename[256] = { 0 };
            //strstr: Returns a pointer to the first occurrence of str2 in str1, or a null pointer if str2 is not part of str1.
            if(strstr((char*)pcap_file, (char*)".pcap"))
            printf("ERROR: could not open pcap file %s: %s\n", pcap_file, pcap_error_buffer);
            else if((getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0)
                || ((pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) == NULL))
            {
                printf("ERROR: could not open playlist %s: %s\n", filename, pcap_error_buffer);
                exit(-1);
            }
            else
            {
                if((!quiet_mode))
                printf("Reading packets from playlist %s...\n", pcap_file);
            }
        }
        else
        {
            if((!quiet_mode))
            printf("Reading packets from pcap file %s...\n", pcap_file);
        }
    }
    else
    {
        live_capture = 1;
        if((!quiet_mode))
        {
// #ifdef USE_DPDK
            // printf("Capturing from DPDK (port 0)...\n");
// #else
            printf("Capturing live traffic from device %s...\n", pcap_file);
// #endif
        }
    }
    configurePcapHandle(pcap_handle);
// #endif /* !DPDK */
    if(capture_for > 0)
    {
        if((!quiet_mode))
            printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);

#ifndef WIN32
        alarm(capture_for);
        signal(SIGALRM, sigproc);
#endif
  }
  return pcap_handle;
}
/**
 * @brief Check pcap packet
 */
static void ndpi_process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ndpi_proto p;
  u_int16_t thread_id = *((u_int16_t*)args);

  /* allocate an exact size buffer to check overflows */
  uint8_t *packet_checked = malloc(header->caplen);

  memcpy(packet_checked, packet, header->caplen);
  p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, packet_checked);
}
/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL))
    // The first argument is our session handle. 
    // Following that is an integer that tells pcap_loop() how many packets it should sniff for before returning (a negative value means it should sniff until an error occurs).
    // The third argument is the name of the callback function (just its identifier, no parentheses).
    // The last argument is passed to the callback function as a parameter.
    pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &ndpi_process_packet, (u_char*)&thread_id);
}
/**
 * @brief Process a running thread
 */
void * processing_thread(void *_thread_id) {
  long thread_id = (long) _thread_id;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];

// #if defined(linux) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
//   if(core_affinity[thread_id] >= 0) {
//     cpu_set_t cpuset;

//     CPU_ZERO(&cpuset);
//     CPU_SET(core_affinity[thread_id], &cpuset);

//     if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
//       fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
//     else {
//       if((!quiet_mode)) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
//     }
//   } else
// #endif
    if((!quiet_mode)) printf("Running thread %ld...\n", thread_id);

// #ifdef USE_DPDK
//   while(dpdk_run_capture) {
//     struct rte_mbuf *bufs[BURST_SIZE];
//     u_int16_t num = rte_eth_rx_burst(dpdk_port_id, 0, bufs, BURST_SIZE);
//     u_int i;

//     if(num == 0) {
//       usleep(1);
//       continue;
//     }

//     for(i = 0; i < PREFETCH_OFFSET && i < num; i++)
//       rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

//     for(i = 0; i < num; i++) {
//       char *data = rte_pktmbuf_mtod(bufs[i], char *);
//       int len = rte_pktmbuf_pkt_len(bufs[i]);
//       struct pcap_pkthdr h;

//       h.len = h.caplen = len;
//       gettimeofday(&h.ts, NULL);

//       ndpi_process_packet((u_char*)&thread_id, &h, (const u_char *)data);
//       rte_pktmbuf_free(bufs[i]);
//     }
//   }
// #else
pcap_loop:
  runPcapLoop(thread_id);

  if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
    char filename[256];

    if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
       (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
      configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
      goto pcap_loop;
    }
  }
// #endif

  return NULL;
}
void test_lib() {
  struct timeval end;
  u_int64_t processing_time_usec, setup_time_usec;
  long thread_id;
  for(thread_id = 0; thread_id < num_threads; thread_id++)
  {
    pcap_t *cap;    
    cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
    setupDetection(thread_id, cap);
  }
  
  gettimeofday(&begin, NULL);

  int status;
  void * thd_res;

  /* Running processing threads */
  for(thread_id = 0; thread_id < num_threads; thread_id++)
  {
    // create a new thread. the new thread starts execution by invoking processing_thread
    // thread_id is passed as an argument to processing_thread
    // If attr is NULL, then the thread is created with default attributes.
    status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
    /* check pthreade_create return value */
    if(status != 0) {
      fprintf(stderr, "error on create %ld thread\n", thread_id);
      exit(-1);
    }
  }
  }