#include "reader_util.h"

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

static struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_workflow * workflow,
						 const u_int8_t version,
						 u_int16_t vlan_id,
						 ndpi_packet_tunnel tunnel_type,
						 const struct ndpi_iphdr *iph,
						 const struct ndpi_ipv6hdr *iph6,
						 u_int16_t ip_offset,
						 u_int16_t ipsize,
						 u_int16_t l4_packet_len,
						 struct ndpi_tcphdr **tcph,
						 struct ndpi_udphdr **udph,
						 u_int16_t *sport, u_int16_t *dport,
						 struct ndpi_id_struct **src,
						 struct ndpi_id_struct **dst,
						 u_int8_t *proto,
						 u_int8_t **payload,
						 u_int16_t *payload_len,
						 u_int8_t *src_to_dst_direction,
                                                 struct timeval when)
{
    //Idx: root number
    u_int32_t idx, l4_offset, hashval;
    struct ndpi_flow_info flow;
    //Returned flow from tfind/tseach
    void * ret;
    const u_int8_t *l3, *l4;
    //Magic number
    u_int32_t l4_data_len = 0xFEEDFACE;


    if(version == IPVERSION)
    {
        //Ensure 20 bytes minimum for IP Header
        if(ipsize < 20)
        {
            return NULL;
        }
    }
    //Ensures that header length isn't bigger than the packet size
    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len))
    {
        return NULL;
    }

}