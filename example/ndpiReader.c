// #include "ndpi_main.h"
// #include <bits/types.h>
// #include <bits/thread-shared-types.h>
#include "ndpi_config.h"

#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <assert.h>
#include <math.h>
#include "ndpi_api.h"
#include "uthash.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libgen.h>

#include "reader_util.h"


/********/
static struct option longopts[] = {
  /* mandatory extcap options */
  { "extcap-interfaces", no_argument, NULL, '0'},
  { "extcap-version", optional_argument, NULL, '1'},
  { "extcap-dlts", no_argument, NULL, '2'},
  { "extcap-interface", required_argument, NULL, '3'},
  { "extcap-config", no_argument, NULL, '4'},
  { "capture", no_argument, NULL, '5'},
  { "extcap-capture-filter", required_argument, NULL, '6'},
  { "fifo", required_argument, NULL, '7'},
  { "debug", no_argument, NULL, '8'},
  { "dbg-proto", required_argument, NULL, 257},
  { "ndpi-proto-filter", required_argument, NULL, '9'},

  /* ndpiReader options */
  { "enable-protocol-guess", no_argument, NULL, 'd'},
  { "categories", required_argument, NULL, 'c'},
  { "csv-dump", required_argument, NULL, 'C'},
  { "interface", required_argument, NULL, 'i'},
  { "filter", required_argument, NULL, 'f'},
  { "cpu-bind", required_argument, NULL, 'g'},
  { "loops", required_argument, NULL, 'l'},
  { "num-threads", required_argument, NULL, 'n'},

  { "protos", required_argument, NULL, 'p'},
  { "capture-duration", required_argument, NULL, 's'},
  { "decode-tunnels", no_argument, NULL, 't'},
  { "revision", no_argument, NULL, 'r'},
  { "verbose", no_argument, NULL, 'v'},
  { "version", no_argument, NULL, 'V'},
  { "help", no_argument, NULL, 'h'},
  { "joy", required_argument, NULL, 'J'},
  { "payload-analysis", required_argument, NULL, 'P'},
  { "result-path", required_argument, NULL, 'w'},
  { "quiet", no_argument, NULL, 'q'},

  {0, 0, 0, 0}
};
/* **********************************************************parseopations************************************************* */

static void parseOptions(int argc, char **argv) {
  int option_idx = 0, do_capture = 0;
  char *__pcap_file = NULL, *bind_mask = NULL;
  int thread_id, opt;
#ifdef linux
  u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif

#ifdef DEBUG_TRACE
  trace = fopen("/tmp/ndpiReader.log", "a");

  if(trace) fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

#ifdef USE_DPDK
  {
    int ret = rte_eal_init(argc, argv);

    if(ret < 0)
      rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret, argv += ret;
  }
#endif

  while((opt = getopt_long(argc, argv, "e:c:C:df:g:i:hp:P:l:s:tv:V:n:Jrp:w:q0123:456:7:89:m:T:U:",
			   longopts, &option_idx)) != EOF) {
#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, " #### -%c [%s] #### \n", opt, optarg ? optarg : "");
#endif

    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'e':
      human_readeable_string_len = atoi(optarg);
      break;

    case 'i':
    case '3':
      _pcap_file[0] = optarg;
      break;

    case 'm':
      pcap_analysis_duration = atol(optarg);
      break;

    case 'f':
    case '6':
      bpfFilter = optarg;
      break;

    case 'g':
      bind_mask = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'n':
      num_threads = atoi(optarg);
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 'c':
      _customCategoryFilePath = optarg;
      break;

    case 'C':
      if((csv_fp = fopen(optarg, "w")) == NULL)
	printf("Unable to write on CSV file %s\n", optarg);
      else
	printCSVHeader();
      break;

    case 's':
      capture_for = atoi(optarg);
      capture_until = capture_for + time(NULL);
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'r':
      printf("ndpiReader - nDPI (%s)\n", ndpi_revision());
      exit(0);

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'V':
      nDPI_LogLevel  = atoi(optarg);
      if(nDPI_LogLevel < 0) nDPI_LogLevel = 0;
      if(nDPI_LogLevel > 3) {
	nDPI_LogLevel = 3;
	_debug_protocols = strdup("all");
      }
      break;

    case 'h':
      help(1);
      break;

    case 'J':
      enable_joy_stats = 1;
      break;

    case 'P':
      {
	int _min_pattern_len, _max_pattern_len,
	  _max_num_packets_per_flow, _max_packet_payload_dissection,
	  _max_num_reported_top_payloads;

	enable_payload_analyzer = 1;
	if(sscanf(optarg, "%d:%d:%d:%d:%d", &_min_pattern_len, &_max_pattern_len,
		  &_max_num_packets_per_flow,
		  &_max_packet_payload_dissection,
		  &_max_num_reported_top_payloads) == 5) {
	  min_pattern_len = _min_pattern_len, max_pattern_len = _max_pattern_len;
	  max_num_packets_per_flow = _max_num_packets_per_flow, max_packet_payload_dissection = _max_packet_payload_dissection;
	  max_num_reported_top_payloads = _max_num_reported_top_payloads;
	  if(min_pattern_len > max_pattern_len) min_pattern_len = max_pattern_len;
	  if(min_pattern_len < 2)               min_pattern_len = 2;
	  if(max_pattern_len > 16)              max_pattern_len = 16;
	  if(max_num_packets_per_flow == 0)     max_num_packets_per_flow = 1;
	  if(max_packet_payload_dissection < 4) max_packet_payload_dissection = 4;
	  if(max_num_reported_top_payloads == 0) max_num_reported_top_payloads = 1;
	} else {
	  printf("Invalid -P format. Ignored\n");
	  help(0);
	}
      }
      break;

    case 'w':
      results_path = strdup(optarg);
      if((results_file = fopen(results_path, "w")) == NULL) {
	printf("Unable to write in file %s: quitting\n", results_path);
	return;
      }
      break;

    case 'q':
      quiet_mode = 1;
      nDPI_LogLevel = 0;
      break;

      /* Extcap */
    case '0':
      extcap_interfaces();
      break;

    case '1':
      printf("extcap {version=%s}\n", ndpi_revision());
      break;

    case '2':
      extcap_dlts();
      break;

    case '4':
      extcap_config();
      break;

    case '5':
      do_capture = 1;
      break;

    case '7':
      extcap_capture_fifo = strdup(optarg);
      break;

    case '8':
      nDPI_LogLevel = NDPI_LOG_DEBUG_EXTRA;
      _debug_protocols = strdup("all");
      break;

    case '9':
      extcap_packet_filter = ndpi_get_proto_by_name(ndpi_info_mod, optarg);
      if(extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN) extcap_packet_filter = atoi(optarg);
      break;

    case 257:
      _debug_protocols = strdup(optarg);
      break;

    case 'T':
      max_num_tcp_dissected_pkts = atoi(optarg);
      if(max_num_tcp_dissected_pkts < 3) max_num_tcp_dissected_pkts = 3;
      break;

    case 'U':
      max_num_udp_dissected_pkts = atoi(optarg);
      if(max_num_udp_dissected_pkts < 3) max_num_udp_dissected_pkts = 3;
      break;

    default:
      help(0);
      break;
    }
  }

  if(_pcap_file[0] == NULL)
    help(0);

#ifndef USE_DPDK
  if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
    num_threads = 0;               /* setting number of threads = number of interfaces */
    __pcap_file = strtok(_pcap_file[0], ",");
    while(__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
      _pcap_file[num_threads++] = __pcap_file;
      __pcap_file = strtok(NULL, ",");
    }
  } else {
    if(num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
    for(thread_id = 1; thread_id < num_threads; thread_id++)
      _pcap_file[thread_id] = _pcap_file[0];
  }

#ifdef linux
    for(thread_id = 0; thread_id < num_threads; thread_id++)
      core_affinity[thread_id] = -1;

    if(num_cores > 1 && bind_mask != NULL) {
      char *core_id = strtok(bind_mask, ":");
      thread_id = 0;
      while(core_id != NULL && thread_id < num_threads) {
        core_affinity[thread_id++] = atoi(core_id) % num_cores;
        core_id = strtok(NULL, ":");
      }
    }
#endif
#endif

#ifdef DEBUG_TRACE
  if(trace) fclose(trace);
#endif
}
















/* ***************************************************************************************************************************** */
/** Client parameters **/

static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static FILE *results_file           = NULL;
static char *results_path           = NULL;
static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path  */
static char *_customCategoryFilePath= NULL; /**< Custom categories file path  */
static FILE *csv_fp                 = NULL; /**< for CSV export */
static u_int8_t live_capture = 0;
//
static struct timeval startup_time, begin, end;
static pcap_dumper_t *extcap_dumper = NULL;
static char extcap_buf[16384];
static char *extcap_capture_fifo    = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t)-1;
static struct timeval pcap_start = { 0, 0}, pcap_end = { 0, 0 };
static u_int8_t undetected_flows_deleted = 0;
/** User preferences **/
u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0;
u_int8_t verbose = 0, enable_joy_stats = 0;
int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16 /* 8 is enough for most protocols, Signal requires more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static struct timeval startup_time, begin, end;
#ifdef linux
static int core_affinity[MAX_NUM_READER_THREADS];
#endif
/** Detection parameters **/
static u_int32_t num_flows;
static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;

extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection, max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;// struct associated to a workflow for a thread
struct reader_thread {
  struct ndpi_workflow *workflow;
  pthread_t pthread;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};
// used memory counters
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;

// array for every thread created for a flow
static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];
  
/* Detection parameters */
static time_t capture_for = 0;
static time_t capture_until = 0;

/**
 * @brief Force a pcap_dispatch() or pcap_loop() call to return
 */
static void breakPcapLoop(u_int16_t thread_id)
{
// #ifdef USE_DPDK
//   dpdk_run_capture = 0;
// #else
  if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
  {
    pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
  }
// #endif
}

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
    // The first argument is our session handle.
    // Following that is a reference to the place we will store the compiled version of our filter.
    // Then comes the expression itself, in regular string format.
    // Next is an integer that decides if the expression should be "optimized" or not (0 is false, 1 is true.)
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
// reads a line from the specified stream (playlist_fp) and stores it into the string pointed to by filename.
// It stops when either (filename_len - 1) characters are read, the newline character is read, or the end-of-file is reached, whichever comes first.
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
/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
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
 * @brief Proto Guess Walker
 */
static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data), proto;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if((!flow->detection_completed) && flow->ndpi_flow) {
      u_int8_t proto_guessed;

      flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct,
						      flow->ndpi_flow, enable_protocol_guess, &proto_guessed);
    }

    process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);

    proto = flow->detected_protocol.app_protocol ? flow->detected_protocol.app_protocol : flow->detected_protocol.master_protocol;

    ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto]       += flow->src2dst_packets + flow->dst2src_packets;
    ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[proto] += flow->src2dst_bytes + flow->dst2src_bytes;
    ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
  }
}

/**
 * @brief Idle Scan Walker
 */
static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if(ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(flow->last_seen + MAX_IDLE_TIME < ndpi_thread_info[thread_id].workflow->last_time) {

      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);

      if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
        undetected_flows_deleted = 1;

      ndpi_free_flow_info_half(flow);
      ndpi_free_flow_data_analysis(flow);
      ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count--;

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
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
  
  //pcap_start => sniffing time of the first packet in the pcap file
  //pcap_end => sniffing time of the last packet
  if(!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
  pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;

  /* Idle flows cleanup */
  if(live_capture)
  {
    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].workflow->last_time)
    {
      /* scan for idle flows */
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],node_idle_scan_walker, &thread_id);

      /* remove idle flows (unfortunately we cannot do this inline) */
      while(ndpi_thread_info[thread_id].num_idle_flows > 0)
      {
	      /* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
	      ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
        &ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
		     ndpi_workflow_node_cmp);

	      /* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
	      ndpi_free_flow_info_half(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
	      ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
      }

      if(++ndpi_thread_info[thread_id].idle_scan_idx == ndpi_thread_info[thread_id].workflow->prefs.num_roots)
	      ndpi_thread_info[thread_id].idle_scan_idx = 0;

      ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].workflow->last_time;
    }
  }

// #ifdef DEBUG_TRACE
//   if(trace) fprintf(trace, "Found %u bytes packet %u.%u\n", header->caplen, p.app_protocol, p.master_protocol);
// #endif

//   if(extcap_dumper
//      && ((extcap_packet_filter == (u_int16_t)-1) || (p.app_protocol == extcap_packet_filter) || (p.master_protocol == extcap_packet_filter)))
//   {
//     struct pcap_pkthdr h;
//     uint32_t *crc, delta = sizeof(struct ndpi_packet_trailer) + 4 /* ethernet trailer */;
//     struct ndpi_packet_trailer *trailer;

//     memcpy(&h, header, sizeof(h));

//     if(h.caplen > (sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4))
//     {
//       printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
//       h.caplen = sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4;
//     }

//     trailer = (struct ndpi_packet_trailer*)&extcap_buf[h.caplen];
//     memcpy(extcap_buf, packet, h.caplen);
//     memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
//     trailer->magic = htonl(0x19680924);
//     trailer->master_protocol = htons(p.master_protocol), trailer->app_protocol = htons(p.app_protocol);
//     ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct, p, trailer->name, sizeof(trailer->name));
//     crc = (uint32_t*)&extcap_buf[h.caplen+sizeof(struct ndpi_packet_trailer)];
//     *crc = ethernet_crc32((const void*)extcap_buf, h.caplen+sizeof(struct ndpi_packet_trailer));
//     h.caplen += delta, h.len += delta;

// // #ifdef DEBUG_TRACE
// //     if(trace) fprintf(trace, "Dumping %u bytes packet\n", h.caplen);
// // #endif

//     pcap_dump((u_char*)extcap_dumper, &h, (const u_char *)extcap_buf);
//     pcap_dump_flush(extcap_dumper);
//   }
  /* check for buffer changes */
  if(memcmp(packet, packet_checked, header->caplen) != 0)
    printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen [thread_id=%u, packetId=%lu, caplen=%u]\n",
	   thread_id, (unsigned long)ndpi_thread_info[thread_id].workflow->stats.raw_packet_count, header->caplen);
  
  if((pcap_end.tv_sec-pcap_start.tv_sec) > pcap_analysis_duration) {
    int i;
    u_int64_t processing_time_usec, setup_time_usec;

    gettimeofday(&end, NULL);
    processing_time_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
    setup_time_usec = begin.tv_sec*1000000 + begin.tv_usec - (startup_time.tv_sec*1000000 + startup_time.tv_usec);

    //printResults(processing_time_usec, setup_time_usec);

    for(i=0; i<ndpi_thread_info[thread_id].workflow->prefs.num_roots; i++) {
      ndpi_tdestroy(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
      ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

      memset(&ndpi_thread_info[thread_id].workflow->stats, 0, sizeof(struct ndpi_stats));
    }

    if(!quiet_mode)
      printf("\n-------------------------------------------\n\n");

    memcpy(&begin, &end, sizeof(begin));
    memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
  }

  /*
     Leave the free as last statement to avoid crashes when ndpi_detection_giveup()
     is called above by printResults()
  */
  free(packet_checked);

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
/* *********************************************** */

/**
 * @brief On Protocol Discover - demo callback
 */
static void on_protocol_discovered(struct ndpi_workflow * workflow,
				   struct ndpi_flow_info * flow,
				   void * udata) {
  ;
}

/* *********************************************** */
/* *********************************************** */

/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id) {
  ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
}

/**
 * @brief Setup for detection begin
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle) {
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_workflow_prefs prefs;

  memset(&prefs, 0, sizeof(prefs));
  prefs.decode_tunnels = decode_tunnels;
  prefs.num_roots = NUM_ROOTS;
  prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
  prefs.quiet_mode = quiet_mode;

  memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
  ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, pcap_handle);

  /* Preferences */
  ndpi_workflow_set_flow_detected_callback(ndpi_thread_info[thread_id].workflow,
					   on_protocol_discovered,
					   (void *)(uintptr_t)thread_id);

  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &all);

  // clear memory for results
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0,
	 sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0,
	 sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0,
	 sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);

  if(_customCategoryFilePath)
    ndpi_load_categories_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _customCategoryFilePath);

  ndpi_finalize_initalization(ndpi_thread_info[thread_id].workflow->ndpi_struct);
}

void test_lib() {
  struct timeval end;
  u_int64_t processing_time_usec, setup_time_usec;
  long thread_id;
// #ifdef DEBUG_TRACE
//   if(trace) fprintf(trace, "Num threads: %d\n", num_threads);
// #endif
  for(thread_id = 0; thread_id < num_threads; thread_id++)
  {
    pcap_t *cap;
// #ifdef DEBUG_TRACE
//     if(trace) fprintf(trace, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
// #endif
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
    // Upon successful creation, pthread_create() stores the ID of the created thread in the location referenced by ndpi_thread_info[thread_id].pthread.
    // If attr is NULL, then the thread is created with default attributes.
    status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
    /* check pthreade_create return value */
    if(status != 0) {
      fprintf(stderr, "error on create %ld thread\n", thread_id);
      exit(-1);
    }
  }
  /* Waiting for completion */
  for(thread_id = 0; thread_id < num_threads; thread_id++)
  {
    status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
    /* check pthreade_join return value */

    // If successful, the pthread_join() function shall return zero; otherwise, an error number shall be returned to indicate the error.
    if(status != 0) {
      fprintf(stderr, "error on join %ld thread\n", thread_id);
      exit(-1);
    }
    if(thd_res != NULL) {
      fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
      exit(-1);
    }
  }
  gettimeofday(&end, NULL);
  processing_time_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
  setup_time_usec = begin.tv_sec*1000000 + begin.tv_usec - (startup_time.tv_sec*1000000 + startup_time.tv_usec);

  /* Printing cumulative results */
  //printResults(processing_time_usec, setup_time_usec);

  for(thread_id = 0; thread_id < num_threads; thread_id++)
  {
    if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
      pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

    terminateDetection(thread_id);
  }
}

  int main(int argc, char **argv) {
    int i;

    
    

    gettimeofday(&startup_time, NULL);
    ndpi_info_mod = ndpi_init_detection_module(ndpi_no_prefs);

    if(ndpi_info_mod == NULL) return -1;

    memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

    //parseOptions(argc, argv);

    if(!quiet_mode) {
      printf("\n-----------------------------------------------------------\n"
	     "* NOTE: This is demo app to show *some* nDPI features.\n"
	     "* In this demo we have implemented only some basic features\n"
	     "* just to show you what you can do with the library. Feel \n"
	     "* free to extend it and send us the patches for inclusion\n"
	     "------------------------------------------------------------\n\n");

      printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);
    }

    signal(SIGINT, sigproc);
    for(i=0; i<num_loops; i++)
      test_lib();

    if(results_path)  free(results_path);
    if(results_file)  fclose(results_file);
    if(extcap_dumper) pcap_dump_close(extcap_dumper);
    if(ndpi_info_mod) ndpi_exit_detection_module(ndpi_info_mod);
    if(csv_fp)        fclose(csv_fp);

    return 0;
  }
