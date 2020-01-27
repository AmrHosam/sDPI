#include "reader_util.h"
#include "ndpi_main.h"
static u_int32_t flow_id = 0;
int ndpi_workflow_node_cmp(const void *a, const void *b) {
  const struct ndpi_flow_info *fa = (const struct ndpi_flow_info*)a;
  const struct ndpi_flow_info *fb = (const struct ndpi_flow_info*)b;

  if(fa->hashval < fb->hashval) return(-1); else if(fa->hashval > fb->hashval) return(1);

  /* Flows have the same hash */

  if(fa->vlan_id   < fb->vlan_id   ) return(-1); else { if(fa->vlan_id    > fb->vlan_id   ) return(1); }
  if(fa->protocol  < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  if(
     (
      (fa->src_ip      == fb->src_ip  )
      && (fa->src_port == fb->src_port)
      && (fa->dst_ip   == fb->dst_ip  )
      && (fa->dst_port == fb->dst_port)
      )
     ||
     (
      (fa->src_ip      == fb->dst_ip  )
      && (fa->src_port == fb->dst_port)
      && (fa->dst_ip   == fb->src_ip  )
      && (fa->dst_port == fb->src_port)
      )
     )
    return(0);

  if(fa->src_ip   < fb->src_ip  ) return(-1); else { if(fa->src_ip   > fb->src_ip  ) return(1); }
  if(fa->src_port < fb->src_port) return(-1); else { if(fa->src_port > fb->src_port) return(1); }
  if(fa->dst_ip   < fb->dst_ip  ) return(-1); else { if(fa->dst_ip   > fb->dst_ip  ) return(1); }
  if(fa->dst_port < fb->dst_port) return(-1); else { if(fa->dst_port > fb->dst_port) return(1); }

  return(0); /* notreached */
}
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
        /*ipv4*/
        //Ensure 20 bytes minimum for IP Header
        if(ipsize < 20)
        {
            return NULL;
        }
    
        //Ensures that header length isn't bigger than the packet size
        if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len))
        {
            return NULL;
        }
        //Offset of transport layer (segment)
        l4_offset = iph->ihl*4;
        l3 = (const u_int8_t)iph;
    }
    else
    {
         /*ipv6*/
        l4_offset = sizeof(struct ndpi_ipv6hdr);
        l3 = (const u_int8_t *) iph6;
    }
    //Keep the transport layer protocol reference
    *proto = iph->protocol;

    #ifdef USE_STATS
            if(l4_packet_len < 64)
          workflow->stats.packet_len[0]++;
        else if(l4_packet_len >= 64 && l4_packet_len < 128)
          workflow->stats.packet_len[1]++;
        else if(l4_packet_len >= 128 && l4_packet_len < 256)
          workflow->stats.packet_len[2]++;
        else if(l4_packet_len >= 256 && l4_packet_len < 1024)
          workflow->stats.packet_len[3]++;
        else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
          workflow->stats.packet_len[4]++;
        else if(l4_packet_len >= 1500)
          workflow->stats.packet_len[5]++;
            
         if(l4_packet_len > workflow->stats.max_packet_len)
            workflow->stats.max_packet_len = l4_packet_len;

    #endif
    //Gets Transport layer pointer
    l4 = ((const u_int8_t *) l3+l4_offset);

    if(*proto == IPPROTO_TCP && l4_packet_len >= sizeof(struct ndpi_tcphdr))
    {
        u_int tcp_len;

        // TCP
        workflow->stats.tcp_count++;
        *tcph = (struct ndpi_tcphdr *)l4;
        *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
        tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
        *payload = (u_int8_t*)&l4[tcp_len];
        *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
        l4_data_len = l4_packet_len - sizeof(struct ndpi_tcphdr);
    }
    else if(*proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct ndpi_udphdr)) 
    {
        // UDP
        workflow->stats.udp_count++;
        *udph = (struct ndpi_udphdr *)l4;
        *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
        *payload = (u_int8_t*)&l4[sizeof(struct ndpi_udphdr)];
        *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len-sizeof(struct ndpi_udphdr) : 0;
        l4_data_len = l4_packet_len - sizeof(struct ndpi_udphdr);
    }
    #ifdef OTHER_TRANSPORT_PROTOCOLS
    else if(*proto == IPPROTO_ICMP) 
    {
        *payload = (u_int8_t*)&l4[sizeof(struct ndpi_icmphdr )];
        *payload_len = (l4_packet_len > sizeof(struct ndpi_icmphdr)) ? l4_packet_len-sizeof(struct ndpi_icmphdr) : 0;
        l4_data_len = l4_packet_len - sizeof(struct ndpi_icmphdr);
        *sport = *dport = 0;
    }
   else if(*proto == IPPROTO_ICMPV6) 
    {
        *payload = (u_int8_t*)&l4[sizeof(struct ndpi_icmp6hdr)];
        *payload_len = (l4_packet_len > sizeof(struct ndpi_icmp6hdr)) ? l4_packet_len-sizeof(struct ndpi_icmp6hdr) : 0;
        l4_data_len = l4_packet_len - sizeof(struct ndpi_icmp6hdr);
        *sport = *dport = 0;
    }
    #endif
    else 
    {
            // non tcp/udp protocols
            *sport = *dport = 0;
            l4_data_len = 0;
    }
    //add flow information
    flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
    flow.src_ip = iph->saddr, flow.dst_ip = iph->daddr;
    flow.src_port = htons(*sport), flow.dst_port = htons(*dport);
    //calculate hashval
    flow.hashval = hashval = flow.protocol + flow.vlan_id + flow.src_ip + flow.dst_ip + flow.src_port + flow.dst_port;
    //choose one root from hashtable for flow
    idx = hashval % workflow->prefs.num_roots;
    //search for flow in the tree with chosen root
    ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);
      /* to avoid two nodes in one binary tree for a flow */
    int is_changed = 0;
    if(ret == NULL) 
    {
        //If still haven't found the flow, we flip to access
        //The rest of the tree
        u_int32_t orig_src_ip = flow.src_ip;
        u_int16_t orig_src_port = flow.src_port;
        u_int32_t orig_dst_ip = flow.dst_ip;
        u_int16_t orig_dst_port = flow.dst_port;

        flow.src_ip = orig_dst_ip;
        flow.src_port = orig_dst_port;
        flow.dst_ip = orig_src_ip;
        flow.dst_port = orig_src_port;

        is_changed = 1;
        
        ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);
    }
    //If still can't find, the flow doesn't exist
    if(ret == NULL) 
    {
        if(workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) 
        {
            NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR,
	        "maximum flow count (%u) has been exceeded\n",
	        workflow->prefs.max_ndpi_flows);
            exit(-1);
        }
        else 
        {
            //Create flow if there is still space
            struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)malloc(sizeof(struct ndpi_flow_info));
            if(newflow == NULL) 
            {
	            NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	            return(NULL);
            }
            //Fill flow info
            workflow->num_allocated_flows++;
            memset(newflow, 0, sizeof(struct ndpi_flow_info));
            newflow->flow_id = flow_id++;
            newflow->hashval = hashval;
            newflow->tunnel_type = tunnel_type;
            newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
            newflow->src_ip = iph->saddr, newflow->dst_ip = iph->daddr;
            newflow->src_port = htons(*sport), newflow->dst_port = htons(*dport);
            newflow->ip_version = version;
            #ifdef DATA_ANALYSIS
            newflow->iat_c_to_s = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	          newflow->iat_s_to_c =  ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);
            newflow->pktlen_c_to_s = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	          newflow->pktlen_s_to_c =  ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	          newflow->iat_flow = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);;
            #endif
            //Converts from binary form to text form (decimal)
            if(version == IPVERSION) 
            {
	            inet_ntop(AF_INET, &newflow->src_ip, newflow->src_name, sizeof(newflow->src_name));
	            inet_ntop(AF_INET, &newflow->dst_ip, newflow->dst_name, sizeof(newflow->dst_name));
            }
            else 
            {
	            inet_ntop(AF_INET6, &iph6->ip6_src, newflow->src_name, sizeof(newflow->src_name));
	            inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->dst_name, sizeof(newflow->dst_name));
	            /* For consistency across platforms replace :0: with :: */
	            ndpi_patchIPv6Address(newflow->src_name), ndpi_patchIPv6Address(newflow->dst_name);
            }
            if((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) 
            {
	            NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	            free(newflow);
	            return(NULL);
            }
            else
            {
	            memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
            }
            if((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) 
            {
	            NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	            free(newflow);
	            return(NULL);
            }
            else
	          {
              memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);
            }
            if((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) 
            {
	            NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	            free(newflow);
	            return(NULL);
            }
            else
	          {
              memset(newflow->dst_id, 0, SIZEOF_ID_STRUCT);
            }
            ndpi_tsearch(newflow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp); /* Add */
            workflow->stats.ndpi_flow_count++;
            *src = newflow->src_id, *dst = newflow->dst_id;
            //Keep data length for current packet
            newflow->entropy.src2dst_pkt_len[newflow->entropy.src2dst_pkt_count] = l4_data_len;
            //keep time for current packet
            newflow->entropy.src2dst_pkt_time[newflow->entropy.src2dst_pkt_count] = when;
            //Set the first packet arrival time in this flow
            if (newflow->entropy.src2dst_pkt_count == 0) 
            {
              newflow->entropy.src2dst_start = when;
            }
            //Set number of packets so far from src to dst
            newflow->entropy.src2dst_pkt_count++;
            // Non zero app data.
            if (l4_data_len != 0XFEEDFACE && l4_data_len != 0) 
            {
              newflow->entropy.src2dst_opackets++;
              newflow->entropy.src2dst_l4_bytes += l4_data_len;
            }
            return newflow;
        }

    }
    else
    {
      //In case of found flow already
      struct ndpi_flow_info *rflow = *(struct ndpi_flow_info**)ret;
      if(is_changed) 
      {
        if(rflow->src_ip == iph->saddr
	        && rflow->dst_ip == iph->daddr
	        && rflow->src_port == htons(*sport)
	        && rflow->dst_port == htons(*dport)
	        )
	      {
          //If flow is reversed with respect to packet
          *src = rflow->dst_id, *dst = rflow->src_id, *src_to_dst_direction = 0, rflow->bidirectional = 1;
        }
        else
	      {
          //If flow is in the same direction as packet
            *src = rflow->src_id, *dst = rflow->dst_id, *src_to_dst_direction = 1;
        } 
      }
      else 
      {
        if(rflow->src_ip == iph->saddr
	      && rflow->dst_ip == iph->daddr
	      && rflow->src_port == htons(*sport)
	      && rflow->dst_port == htons(*dport)
	      )
        {
          //Flow in the same direction as packet
	        *src = rflow->src_id, *dst = rflow->dst_id, *src_to_dst_direction = 1;
        }
        else
	      {
          //Flow in reversed direction with respect to packet
        *src = rflow->dst_id, *dst = rflow->src_id, *src_to_dst_direction = 0, rflow->bidirectional = 1;
        }
      }
      //If packet is in the same direction as flow
      if (src_to_dst_direction) 
      {
        if (rflow->entropy.src2dst_pkt_count < max_num_packets_per_flow) 
        {
          rflow->entropy.src2dst_pkt_len[rflow->entropy.src2dst_pkt_count] = l4_data_len;
          rflow->entropy.src2dst_pkt_time[rflow->entropy.src2dst_pkt_count] = when;
          rflow->entropy.src2dst_l4_bytes += l4_data_len;
          rflow->entropy.src2dst_pkt_count++;
        }
      // Non zero app data.
        if (l4_data_len != 0XFEEDFACE && l4_data_len != 0) 
        {
          rflow->entropy.src2dst_opackets++;
        }
      } 
      else 
      {
        //If packet was in the opposite direction with respect to flow
        if (rflow->entropy.dst2src_pkt_count < max_num_packets_per_flow) 
        {
          rflow->entropy.dst2src_pkt_len[rflow->entropy.dst2src_pkt_count] = l4_data_len;
          rflow->entropy.dst2src_pkt_time[rflow->entropy.dst2src_pkt_count] = when;
          if (rflow->entropy.dst2src_pkt_count == 0) 
          {
            rflow->entropy.dst2src_start = when;
          }
          rflow->entropy.dst2src_l4_bytes += l4_data_len;
          rflow->entropy.dst2src_pkt_count++;
        }
      // Non zero app data.
        if (l4_data_len != 0XFEEDFACE && l4_data_len != 0) 
        {
          rflow->entropy.dst2src_opackets++;
        }
      } 
      return(rflow); 
    }

    

}