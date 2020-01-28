#include "uthash.h"
#include <pcap.h>
#define MAX_NUM_READER_THREADS     16
#include "ndpi_includes.h"
#include "notsure.h"
// flow tracking
typedef struct ndpi_flow_info {
  u_int32_t flow_id;
  u_int32_t hashval;
  u_int32_t src_ip;
  u_int32_t dst_ip;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t detection_completed, protocol, bidirectional, check_extra_packets;
  u_int16_t vlan_id;
  ndpi_packet_tunnel tunnel_type;
  struct ndpi_flow_struct *ndpi_flow;
  char src_name[48], dst_name[48];
  u_int8_t ip_version;
  u_int64_t first_seen, last_seen;
  u_int64_t src2dst_bytes, dst2src_bytes;
  u_int64_t src2dst_goodput_bytes, dst2src_goodput_bytes;
  u_int32_t src2dst_packets, dst2src_packets;
  u_int32_t has_human_readeable_strings;
  char human_readeable_string_buffer[32];
  
  // result only, not used for flow identification
  ndpi_protocol detected_protocol;

  // Flow data analysis
  struct ndpi_analyze_struct *iat_c_to_s, *iat_s_to_c, *iat_flow,
    *pktlen_c_to_s, *pktlen_s_to_c;
    
  char info[96];
  char host_server_name[256];
  char bittorent_hash[41];
  char dhcp_fingerprint[48];

  struct {
    u_int16_t ssl_version;
    char client_info[64], server_info[64],
      client_hassh[33], server_hassh[33],
      server_organization[64],
      ja3_client[33], ja3_server[33],
      sha1_cert_fingerprint[20];
    time_t notBefore, notAfter;
    u_int16_t server_cipher;
    ndpi_cipher_weakness client_unsafe_cipher, server_unsafe_cipher;    
  } ssh_tls;

  struct {
    char url[256], content_type[64], user_agent[128];
    u_int response_status_code;
  } http;
  
  struct {
    char username[32], password[32];
  } telnet;
  
  void *src_id, *dst_id;

  struct ndpi_entropy entropy;
  struct ndpi_entropy last_entropy;  
} ndpi_flow_info_t;
// workflow main structure
typedef struct ndpi_workflow {
  u_int64_t last_time;

  struct ndpi_workflow_prefs prefs;
  struct ndpi_stats stats;

  ndpi_workflow_callback_ptr __flow_detected_callback;
  void * __flow_detected_udata;
  ndpi_workflow_callback_ptr __flow_giveup_callback;
  void * __flow_giveup_udata;

  /* outside referencies */
  pcap_t *pcap_handle;

  /* allocated by prefs */
  void **ndpi_flows_root;
  struct ndpi_detection_module_struct *ndpi_struct;
  u_int32_t num_allocated_flows;
 } ndpi_workflow_t;
