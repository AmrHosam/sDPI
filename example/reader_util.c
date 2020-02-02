/*
 * reader_util.c
 *
 * Copyright (C) 2011-19 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "ndpi_config.h"
#endif

#include <stdlib.h>

#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#include <math.h>
#include <float.h>
#endif

#ifndef ETH_P_IP
#define ETH_P_IP               0x0800 	/* IPv4 */
#endif

#ifndef ETH_P_IPv6
#define ETH_P_IPV6	       0x86dd	/* IPv6 */
#endif

#define SLARP                  0x8035   /* Cisco Slarp */
#define CISCO_D_PROTO          0x2000	/* Cisco Discovery Protocol */

#define VLAN                   0x8100
#define MPLS_UNI               0x8847
#define MPLS_MULTI             0x8848
#define PPPoE                  0x8864
#define SNAP                   0xaa
#define BSTP                   0x42     /* Bridge Spanning Tree Protocol */

/* Keep last 32 packets */
#define DATA_ANALUYSIS_SLIDING_WINDOW    32

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)

/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

#define GTP_U_V1_PORT                  2152
#define NDPI_CAPWAP_DATA_PORT          5247
#define TZSP_PORT                      37008

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL  113
#endif

#include "ndpi_main.h"
#include "reader_util.h"
#include "ndpi_classify.h"

extern u_int8_t enable_protocol_guess, enable_joy_stats, enable_payload_analyzer;
extern u_int8_t verbose, human_readeable_string_len;
extern u_int8_t max_num_udp_dissected_pkts /* 8 */, max_num_tcp_dissected_pkts /* 10 */;

static u_int32_t flow_id = 0;
/* ****************************************************** */

struct flow_id_stats {
  u_int32_t flow_id;
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct packet_id_stats {
  u_int32_t packet_id;
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct payload_stats {
  u_int8_t *pattern;
  u_int8_t pattern_len;
  u_int16_t num_occurrencies;
  struct flow_id_stats *flows;
  struct packet_id_stats *packets;
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct payload_stats *pstats = NULL;
u_int32_t max_num_packets_per_flow = 10; /* ETTA requires min 10 pkts for record. */
u_int32_t max_packet_payload_dissection = 128;
u_int32_t max_num_reported_top_payloads = 25;
u_int16_t min_pattern_len = 4;
u_int16_t max_pattern_len = 8;

int ndpi_workflow_node_cmp(const void *a, const void *b)
{
  const struct ndpi_flow_info *fa = (const struct ndpi_flow_info *)a;
  const struct ndpi_flow_info *fb = (const struct ndpi_flow_info *)b;

  if (fa->hashval < fb->hashval)
    return (-1);
  else if (fa->hashval > fb->hashval)
    return (1);

  /* Flows have the same hash */

  if (fa->vlan_id < fb->vlan_id)
    return (-1);
  else
  {
    if (fa->vlan_id > fb->vlan_id)
      return (1);
  }
  if (fa->protocol < fb->protocol)
    return (-1);
  else
  {
    if (fa->protocol > fb->protocol)
      return (1);
  }

  if (
      (
          (fa->src_ip == fb->src_ip) && (fa->src_port == fb->src_port) && (fa->dst_ip == fb->dst_ip) && (fa->dst_port == fb->dst_port)) ||
      ((fa->src_ip == fb->dst_ip) && (fa->src_port == fb->dst_port) && (fa->dst_ip == fb->src_ip) && (fa->dst_port == fb->src_port)))
    return (0);

  if (fa->src_ip < fb->src_ip)
    return (-1);
  else
  {
    if (fa->src_ip > fb->src_ip)
      return (1);
  }
  if (fa->src_port < fb->src_port)
    return (-1);
  else
  {
    if (fa->src_port > fb->src_port)
      return (1);
  }
  if (fa->dst_ip < fb->dst_ip)
    return (-1);
  else
  {
    if (fa->dst_ip > fb->dst_ip)
      return (1);
  }
  if (fa->dst_port < fb->dst_port)
    return (-1);
  else
  {
    if (fa->dst_port > fb->dst_port)
      return (1);
  }

  return (0); /* notreached */
}
/* ***************************************************** */

extern u_int32_t current_ndpi_memory, max_ndpi_memory;

/**
 * @brief malloc wrapper function
 */
static void *malloc_wrapper(size_t size)
{
  current_ndpi_memory += size;

  if (current_ndpi_memory > max_ndpi_memory)
    max_ndpi_memory = current_ndpi_memory;

  return malloc(size);
}
/* ***************************************************** */

void ndpi_free_flow_info_half(struct ndpi_flow_info *flow)
{
  if (flow->ndpi_flow)
  {
    ndpi_flow_free(flow->ndpi_flow);
    flow->ndpi_flow = NULL;
  }
  if (flow->src_id)
  {
    ndpi_free(flow->src_id);
    flow->src_id = NULL;
  }
  if (flow->dst_id)
  {
    ndpi_free(flow->dst_id);
    flow->dst_id = NULL;
  }
}

/* ***************************************************** */
/* ***************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_workflow *workflow,
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
  void *ret;
  const u_int8_t *l3, *l4;
  //Magic number
  u_int32_t l4_data_len = 0xFEEDFACE;

  if (version == IPVERSION)
  {
    /*ipv4*/
    //Ensure 20 bytes minimum for IP Header
    if (ipsize < 20)
    {
      return NULL;
    }

    //Ensures that header length isn't bigger than the packet size
    if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len))
    {
      return NULL;
    }
    //Offset of transport layer (segment)
    l4_offset = iph->ihl * 4;
    l3 = (const u_int8_t*)iph;
  }
  else
  {
    /*ipv6*/
    l4_offset = sizeof(struct ndpi_ipv6hdr);
    l3 = (const u_int8_t *)iph6;
  }
  //Keep the transport layer protocol reference
  *proto = iph->protocol;

#ifdef USE_STATS
  if (l4_packet_len < 64)
    workflow->stats.packet_len[0]++;
  else if (l4_packet_len >= 64 && l4_packet_len < 128)
    workflow->stats.packet_len[1]++;
  else if (l4_packet_len >= 128 && l4_packet_len < 256)
    workflow->stats.packet_len[2]++;
  else if (l4_packet_len >= 256 && l4_packet_len < 1024)
    workflow->stats.packet_len[3]++;
  else if (l4_packet_len >= 1024 && l4_packet_len < 1500)
    workflow->stats.packet_len[4]++;
  else if (l4_packet_len >= 1500)
    workflow->stats.packet_len[5]++;

  if (l4_packet_len > workflow->stats.max_packet_len)
    workflow->stats.max_packet_len = l4_packet_len;

#endif
  //Gets Transport layer pointer
  l4 = ((const u_int8_t *)l3 + l4_offset);

  if (*proto == IPPROTO_TCP && l4_packet_len >= sizeof(struct ndpi_tcphdr))
  {
    u_int tcp_len;

    // TCP
    workflow->stats.tcp_count++;
    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
    tcp_len = ndpi_min(4 * (*tcph)->doff, l4_packet_len);
    *payload = (u_int8_t *)&l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len - 4 * (*tcph)->doff);
    l4_data_len = l4_packet_len - sizeof(struct ndpi_tcphdr);
  }
  else if (*proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct ndpi_udphdr))
  {
    // UDP
    workflow->stats.udp_count++;
    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
    *payload = (u_int8_t *)&l4[sizeof(struct ndpi_udphdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len - sizeof(struct ndpi_udphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_udphdr);
  }
#ifdef OTHER_TRANSPORT_PROTOCOLS
  else if (*proto == IPPROTO_ICMP)
  {
    *payload = (u_int8_t *)&l4[sizeof(struct ndpi_icmphdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_icmphdr)) ? l4_packet_len - sizeof(struct ndpi_icmphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_icmphdr);
    *sport = *dport = 0;
  }
  else if (*proto == IPPROTO_ICMPV6)
  {
    *payload = (u_int8_t *)&l4[sizeof(struct ndpi_icmp6hdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_icmp6hdr)) ? l4_packet_len - sizeof(struct ndpi_icmp6hdr) : 0;
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
  if (ret == NULL)
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
  if (ret == NULL)
  {
    if (workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows)
    {
      NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR,
               "maximum flow count (%u) has been exceeded\n",
               workflow->prefs.max_ndpi_flows);
      exit(-1);
    }
    else
    {
      //Create flow if there is still space
      struct ndpi_flow_info *newflow = (struct ndpi_flow_info *)malloc(sizeof(struct ndpi_flow_info));
      if (newflow == NULL)
      {
        NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
        return (NULL);
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
      newflow->iat_s_to_c = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);
      newflow->pktlen_c_to_s = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
      newflow->pktlen_s_to_c = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
      newflow->iat_flow = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);
      ;
#endif
      //Converts from binary form to text form (decimal)
      if (version == IPVERSION)
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
      if ((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL)
      {
        NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
        free(newflow);
        return (NULL);
      }
      else
      {
        memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
      }
      if ((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL)
      {
        NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
        free(newflow);
        return (NULL);
      }
      else
      {
        memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);
      }
      if ((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL)
      {
        NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(4): not enough memory\n", __FUNCTION__);
        free(newflow);
        return (NULL);
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
    struct ndpi_flow_info *rflow = *(struct ndpi_flow_info **)ret;
    if (is_changed)
    {
      if (rflow->src_ip == iph->saddr && rflow->dst_ip == iph->daddr && rflow->src_port == htons(*sport) && rflow->dst_port == htons(*dport))
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
      if (rflow->src_ip == iph->saddr && rflow->dst_ip == iph->daddr && rflow->src_port == htons(*sport) && rflow->dst_port == htons(*dport))
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
    return (rflow);
  }
}
/* ****************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info6(struct ndpi_workflow *workflow,
                                                  u_int16_t vlan_id,
                                                  ndpi_packet_tunnel tunnel_type,
                                                  const struct ndpi_ipv6hdr *iph6,
                                                  u_int16_t ip_offset,
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
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  iph.protocol = iph6->ip6_hdr.ip6_un1_nxt;

  if (iph.protocol == IPPROTO_DSTOPTS /* IPv6 destination option */)
  {
    const u_int8_t *options = (const u_int8_t *)iph6 + sizeof(const struct ndpi_ipv6hdr);

    iph.protocol = options[0];
  }

  return (get_ndpi_flow_info(workflow, 6, vlan_id, tunnel_type,
                             &iph, iph6, ip_offset,
                             sizeof(struct ndpi_ipv6hdr),
                             ntohs(iph6->ip6_hdr.ip6_un1_plen),
                             tcph, udph, sport, dport,
                             src, dst, proto, payload,
                             payload_len, src_to_dst_direction, when));
}
/* *********************************************************** */
/* *********************************************************** */

void ndpi_analyze_payload(struct ndpi_flow_info *flow,
                          u_int8_t src_to_dst_direction,
                          u_int8_t *payload,
                          u_int16_t payload_len,
                          u_int32_t packet_id)
{
  struct payload_stats *ret;
  struct flow_id_stats *f;
  struct packet_id_stats *p;

#ifdef DEBUG_PAYLOAD
  for (i = 0; i < payload_len; i++)
    printf("%c", isprint(payload[i]) ? payload[i] : '.');
  printf("\n");
#endif

  HASH_FIND(hh, pstats, payload, payload_len, ret);
  if (ret == NULL)
  {
    if ((ret = (struct payload_stats *)calloc(1, sizeof(struct payload_stats))) == NULL)
      return; /* OOM */

    if ((ret->pattern = (u_int8_t *)malloc(payload_len)) == NULL)
    {
      free(ret);
      return;
    }

    memcpy(ret->pattern, payload, payload_len);
    ret->pattern_len = payload_len;
    ret->num_occurrencies = 1;
    HASH_ADD(hh, pstats, pattern[0], payload_len, ret);

#ifdef DEBUG_PAYLOAD
    printf("Added element [total: %u]\n", HASH_COUNT(pstats));
#endif
  }
  else
  {
    ret->num_occurrencies++;
    // printf("==> %u\n", ret->num_occurrencies);
  }

  HASH_FIND_INT(ret->flows, &flow->flow_id, f);
  if (f == NULL)
  {
    if ((f = (struct flow_id_stats *)calloc(1, sizeof(struct flow_id_stats))) == NULL)
      return; /* OOM */

    f->flow_id = flow->flow_id;
    HASH_ADD_INT(ret->flows, flow_id, f);
  }

  HASH_FIND_INT(ret->packets, &packet_id, p);
  if (p == NULL)
  {
    if ((p = (struct packet_id_stats *)calloc(1, sizeof(struct packet_id_stats))) == NULL)
      return; /* OOM */
    p->packet_id = packet_id;

    HASH_ADD_INT(ret->packets, packet_id, p);
  }
}
/* ****************************************************** */

void ndpi_payload_analyzer(struct ndpi_flow_info *flow,
                           u_int8_t src_to_dst_direction,
                           u_int8_t *payload, u_int16_t payload_len,
                           u_int32_t packet_id)
{
  u_int16_t i, j;
  u_int16_t scan_len = ndpi_min(max_packet_payload_dissection, payload_len);

  if ((flow->src2dst_packets + flow->dst2src_packets) <= max_num_packets_per_flow)
  {
#ifdef DEBUG_PAYLOAD
    printf("[hashval: %u][proto: %u][vlan: %u][%s:%u <-> %s:%u][direction: %s][payload_len: %u]\n",
           flow->hashval, flow->protocol, flow->vlan_id,
           flow->src_name, flow->src_port,
           flow->dst_name, flow->dst_port,
           src_to_dst_direction ? "s2d" : "d2s",
           payload_len);
#endif
  }
  else
    return;

  for (i = 0; i < scan_len; i++)
  {
    for (j = min_pattern_len; j <= max_pattern_len; j++)
    {
      if ((i + j) < payload_len)
      {
        ndpi_analyze_payload(flow, src_to_dst_direction, &payload[i], j, packet_id);
      }
    }
  }
}

/**
 * @brief Clear entropy stats if it meets prereq.
 */
static void
ndpi_clear_entropy_stats(struct ndpi_flow_info *flow)
{
  if (flow->entropy.src2dst_pkt_count + flow->entropy.dst2src_pkt_count == max_num_packets_per_flow)
  {
    memcpy(&flow->last_entropy, &flow->entropy, sizeof(struct ndpi_entropy));
    memset(&flow->entropy, 0x00, sizeof(struct ndpi_entropy));
  }
}
/* ****************************************************** */

static u_int8_t is_ndpi_proto(struct ndpi_flow_info *flow, u_int16_t id)
{
  if ((flow->detected_protocol.master_protocol == id) || (flow->detected_protocol.app_protocol == id))
    return (1);
  else
    return (0);
}

/* ****************************************************** */
/* ***************************************************** */


/* ****************************************************** */

void process_ndpi_collected_info(struct ndpi_workflow *workflow, struct ndpi_flow_info *flow)
{
  if (!flow->ndpi_flow)
    return;

  snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s",
           flow->ndpi_flow->host_server_name);

  if (is_ndpi_proto(flow, NDPI_PROTOCOL_DHCP))
  {
    snprintf(flow->dhcp_fingerprint, sizeof(flow->dhcp_fingerprint), "%s", flow->ndpi_flow->protos.dhcp.fingerprint);
  }
  else if (is_ndpi_proto(flow, NDPI_PROTOCOL_BITTORRENT))
  {
    u_int i, j, n = 0;

    for (i = 0, j = 0; j < sizeof(flow->bittorent_hash) - 1; i++)
    {
      sprintf(&flow->bittorent_hash[j], "%02x",
              flow->ndpi_flow->protos.bittorrent.hash[i]);

      j += 2, n += flow->ndpi_flow->protos.bittorrent.hash[i];
    }

    if (n == 0)
      flow->bittorent_hash[0] = '\0';
  }
  /* MDNS */
  else if (is_ndpi_proto(flow, NDPI_PROTOCOL_MDNS))
  {
    snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.mdns.answer);
  }
  /* UBNTAC2 */
  else if (is_ndpi_proto(flow, NDPI_PROTOCOL_UBNTAC2))
  {
    snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.ubntac2.version);
  }
  /* FTP */
  else if ((is_ndpi_proto(flow, NDPI_PROTOCOL_FTP_CONTROL)) || /* IMAP */ is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_IMAP) || /* POP */ is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_POP) || /* SMTP */ is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_SMTP))
  {
    if (flow->ndpi_flow->protos.ftp_imap_pop_smtp.username[0] != '\0')
      snprintf(flow->info, sizeof(flow->info), "User: %s][Pwd: %s%s",
               flow->ndpi_flow->protos.ftp_imap_pop_smtp.username,
               flow->ndpi_flow->protos.ftp_imap_pop_smtp.password,
               flow->ndpi_flow->protos.ftp_imap_pop_smtp.auth_failed ? "][Auth Failed" : "");
  }
  /* KERBEROS */
  else if (is_ndpi_proto(flow, NDPI_PROTOCOL_KERBEROS))
  {
    if ((flow->ndpi_flow->protos.kerberos.hostname[0] != '\0') || (flow->ndpi_flow->protos.kerberos.username[0] != '\0'))
    {
      snprintf(flow->info, sizeof(flow->info), "%s%s (%s)",
               flow->ndpi_flow->protos.kerberos.hostname,
               flow->ndpi_flow->protos.kerberos.username,
               flow->ndpi_flow->protos.kerberos.domain);
    }
  }
  /* HTTP */
  else if ((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_HTTP) || is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP))
  {
    if (flow->ndpi_flow->http.url != NULL)
    {
      snprintf(flow->http.url, sizeof(flow->http.url), "%s", flow->ndpi_flow->http.url);
      flow->http.response_status_code = flow->ndpi_flow->http.response_status_code;
      snprintf(flow->http.content_type, sizeof(flow->http.content_type), "%s", flow->ndpi_flow->http.content_type ? flow->ndpi_flow->http.content_type : "");
      snprintf(flow->http.user_agent, sizeof(flow->http.user_agent), "%s", flow->ndpi_flow->http.user_agent ? flow->ndpi_flow->http.user_agent : "");
    }
  }
  else if (is_ndpi_proto(flow, NDPI_PROTOCOL_TELNET))
  {
    snprintf(flow->telnet.username, sizeof(flow->telnet.username), "%s", flow->ndpi_flow->protos.telnet.username);
    snprintf(flow->telnet.password, sizeof(flow->telnet.password), "%s", flow->ndpi_flow->protos.telnet.password);
  }
  else if (is_ndpi_proto(flow, NDPI_PROTOCOL_SSH))
  {
    snprintf(flow->ssh_tls.client_info, sizeof(flow->ssh_tls.client_info), "%s",
             flow->ndpi_flow->protos.ssh.client_signature);
    snprintf(flow->ssh_tls.server_info, sizeof(flow->ssh_tls.server_info), "%s",
             flow->ndpi_flow->protos.ssh.server_signature);
    snprintf(flow->ssh_tls.client_hassh, sizeof(flow->ssh_tls.client_hassh), "%s",
             flow->ndpi_flow->protos.ssh.hassh_client);
    snprintf(flow->ssh_tls.server_hassh, sizeof(flow->ssh_tls.server_hassh), "%s",
             flow->ndpi_flow->protos.ssh.hassh_server);
  }
  /* TLS */
  else if ((is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)) || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS) || (flow->ndpi_flow->protos.stun_ssl.ssl.ja3_client[0] != '\0'))
  {
    flow->ssh_tls.ssl_version = flow->ndpi_flow->protos.stun_ssl.ssl.ssl_version;
    snprintf(flow->ssh_tls.client_info, sizeof(flow->ssh_tls.client_info), "%s",
             flow->ndpi_flow->protos.stun_ssl.ssl.client_certificate);
    snprintf(flow->ssh_tls.server_info, sizeof(flow->ssh_tls.server_info), "%s",
             flow->ndpi_flow->protos.stun_ssl.ssl.server_certificate);
    snprintf(flow->ssh_tls.server_organization, sizeof(flow->ssh_tls.server_organization), "%s",
             flow->ndpi_flow->protos.stun_ssl.ssl.server_organization);
    flow->ssh_tls.notBefore = flow->ndpi_flow->protos.stun_ssl.ssl.notBefore;
    flow->ssh_tls.notAfter = flow->ndpi_flow->protos.stun_ssl.ssl.notAfter;
    snprintf(flow->ssh_tls.ja3_client, sizeof(flow->ssh_tls.ja3_client), "%s",
             flow->ndpi_flow->protos.stun_ssl.ssl.ja3_client);
    snprintf(flow->ssh_tls.ja3_server, sizeof(flow->ssh_tls.ja3_server), "%s",
             flow->ndpi_flow->protos.stun_ssl.ssl.ja3_server);
    flow->ssh_tls.server_unsafe_cipher = flow->ndpi_flow->protos.stun_ssl.ssl.server_unsafe_cipher;
    flow->ssh_tls.server_cipher = flow->ndpi_flow->protos.stun_ssl.ssl.server_cipher;
    memcpy(flow->ssh_tls.sha1_cert_fingerprint,
           flow->ndpi_flow->l4.tcp.tls_sha1_certificate_fingerprint, 20);
  }

  if (flow->detection_completed && (!flow->check_extra_packets))
  {
    if (is_ndpi_proto(flow, NDPI_PROTOCOL_UNKNOWN))
    {
      if (workflow->__flow_giveup_callback != NULL)
        workflow->__flow_giveup_callback(workflow, flow, workflow->__flow_giveup_udata);
    }
    else
    {
      if (workflow->__flow_detected_callback != NULL)
        workflow->__flow_detected_callback(workflow, flow, workflow->__flow_detected_udata);
    }

    ndpi_free_flow_info_half(flow);
  }
}

/* ****************************************************** */
/************************************************* */

static struct ndpi_proto packet_processing(struct ndpi_workflow *workflow,
                                           const u_int64_t time,
                                           u_int16_t vlan_id,
                                           ndpi_packet_tunnel tunnel_type,
                                           const struct ndpi_iphdr *iph,
                                           struct ndpi_ipv6hdr *iph6,
                                           u_int16_t ip_offset,
                                           u_int16_t ipsize, u_int16_t rawsize,
                                           const struct pcap_pkthdr *header,
                                           const u_char *packet,
                                           struct timeval when)
{
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow_info *flow = NULL;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len = 0;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction = 1;
  u_int8_t begin_or_end_tcp = 0;
  struct ndpi_proto nproto = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN};

  if (iph)
  {
    flow = get_ndpi_flow_info(workflow, IPVERSION, vlan_id,
                              tunnel_type, iph, NULL,
                              ip_offset, ipsize,
                              ntohs(iph->tot_len) - (iph->ihl * 4),
                              &tcph, &udph, &sport, &dport,
                              &src, &dst, &proto,
                              &payload, &payload_len, &src_to_dst_direction, when);
  }
  else
  {
    flow = get_ndpi_flow_info6(workflow, vlan_id,
                               tunnel_type, iph6, ip_offset,
                               &tcph, &udph, &sport, &dport,
                               &src, &dst, &proto,
                               &payload, &payload_len, &src_to_dst_direction, when);
  }
  if (flow != NULL)
  {
    struct timeval tdiff;

    workflow->stats.ip_packet_count++;
    workflow->stats.total_wire_bytes += rawsize + 24 /* CRC etc */,
        workflow->stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;

    if ((tcph != NULL) && (tcph->fin || tcph->rst || tcph->syn))
      begin_or_end_tcp = 1;
    if (flow->entropy.flow_last_pkt_time.tv_sec)
    {
      ndpi_timer_sub(&when, &flow->entropy.flow_last_pkt_time, &tdiff);
      if (flow->iat_flow)
      {
        u_int32_t ms = ndpi_timeval_to_milliseconds(tdiff);

        if (ms > 0)
          ndpi_data_add_value(flow->iat_flow, ms);
      }
    }
    memcpy(&flow->entropy.flow_last_pkt_time, &when, sizeof(when));
    if (src_to_dst_direction)
    {
      if (flow->entropy.src2dst_last_pkt_time.tv_sec)
      {
        ndpi_timer_sub(&when, &flow->entropy.src2dst_last_pkt_time, &tdiff);

        if (flow->iat_c_to_s)
        {
          u_int32_t ms = ndpi_timeval_to_milliseconds(tdiff);

          ndpi_data_add_value(flow->iat_c_to_s, ms);
        }
      }

      ndpi_data_add_value(flow->pktlen_c_to_s, rawsize);
      flow->src2dst_packets++, flow->src2dst_bytes += rawsize, flow->src2dst_goodput_bytes += payload_len;
      memcpy(&flow->entropy.src2dst_last_pkt_time, &when, sizeof(when));
    }
    else
    {
      if (flow->entropy.dst2src_last_pkt_time.tv_sec && (!begin_or_end_tcp))
      {
        ndpi_timer_sub(&when, &flow->entropy.dst2src_last_pkt_time, &tdiff);

        if (flow->iat_s_to_c)
        {
          u_int32_t ms = ndpi_timeval_to_milliseconds(tdiff);

          ndpi_data_add_value(flow->iat_s_to_c, ms);
        }
      }

      ndpi_data_add_value(flow->pktlen_s_to_c, rawsize);
      flow->dst2src_packets++, flow->dst2src_bytes += rawsize, flow->dst2src_goodput_bytes += payload_len;
      memcpy(&flow->entropy.dst2src_last_pkt_time, &when, sizeof(when));
    }
    if (0 && (payload_len > 0))
      ndpi_payload_analyzer(flow, src_to_dst_direction,
                            payload, payload_len,
                            workflow->stats.ip_packet_count);

    if (flow->first_seen == 0)
      flow->first_seen = time;

    flow->last_seen = time;

    /* Copy packets entropy if num packets count == 10 */
    ndpi_clear_entropy_stats(flow);
    if (!flow->has_human_readeable_strings)
    {
      u_int8_t skip = 0;
      // TCP AND (TLS or SSH) AND PACKETS LESS THAN TEN
      if ((proto == IPPROTO_TCP) && (is_ndpi_proto(flow, NDPI_PROTOCOL_TLS) || /*(flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS) || */ is_ndpi_proto(flow, NDPI_PROTOCOL_SSH) /*|| (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSH*/) && ((flow->src2dst_packets + flow->dst2src_packets) < 10 /* MIN_NUM_ENCRYPT_SKIP_PACKETS */))
      {
        //Do not check for human readable strings
        skip = 1;
      }

      if (!skip)
      {
        if (ndpi_has_human_readeable_string(workflow->ndpi_struct, (char *)packet, header->caplen,
                                            human_readeable_string_len,
                                            flow->human_readeable_string_buffer,
                                            sizeof(flow->human_readeable_string_buffer)) == 1)
          flow->has_human_readeable_strings = 1;
      }
    }
    else
    {
      if ((proto == IPPROTO_TCP) && (is_ndpi_proto(flow, NDPI_PROTOCOL_TLS) || /* (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS) ||*/ is_ndpi_proto(flow, NDPI_PROTOCOL_SSH) /* ||  (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSH)*/))
      {
        flow->has_human_readeable_strings = 0;
      }
    }
  }
  else
  {                                          // flow is NULL
    workflow->stats.total_discarded_bytes++; //PACKETS NOT BYTES
    return (nproto);
  }
  if (!flow->detection_completed)
  {
    u_int enough_packets =
        (((proto == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > max_num_udp_dissected_pkts)) || ((proto == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > max_num_tcp_dissected_pkts))) ? 1 : 0;

    flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
                                                            iph ? (uint8_t *)iph : (uint8_t *)iph6,
                                                            ipsize, time, src, dst);

    if (enough_packets || (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    {
      // not enough packets and protocol is KNOWN we check for further dissection
      if ((!enough_packets) && ndpi_extra_dissection_possible(workflow->ndpi_struct, ndpi_flow))
        ;  /* Wait for certificate fingerprint */
      else //enough packets or no further dissection
      {
        /* New protocol detected or give up */
        flow->detection_completed = 1;
        //giveup if protocol is still unknown
        if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
        {
          u_int8_t proto_guessed;

          flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow,
                                                          enable_protocol_guess, &proto_guessed);
        }

        process_ndpi_collected_info(workflow, flow);
      }
    }
  }

  return (flow->detected_protocol);
}
struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow *workflow, const struct pcap_pkthdr *header, const u_char *packet)
{
  /*
   * Declare pointers to packet headers
   */
  /* --- Ethernet header --- */
  const struct ndpi_ethhdr *ethernet;
  /* --- LLC header --- */
  const struct ndpi_llc_header_snap *llc;

  /* --- Cisco HDLC header --- */
  const struct ndpi_chdlc *chdlc;

  /* --- Radio Tap header --- */
  const struct ndpi_radiotap_header *radiotap;
  /* --- Wifi header --- */
  const struct ndpi_wifi_header *wifi;

  /* --- MPLS header --- */
  union mpls {
    uint32_t u32;
    struct ndpi_mpls_header mpls;
  } mpls;

  /** --- IP header --- **/
  struct ndpi_iphdr *iph;
  /** --- IPv6 header --- **/
  struct ndpi_ipv6hdr *iph6;

  struct ndpi_proto nproto = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN};
  ndpi_packet_tunnel tunnel_type = ndpi_no_tunnel;

  /* lengths and offsets */
  u_int16_t eth_offset = 0;
  u_int16_t radio_len;
  u_int16_t fc;
  u_int16_t type = 0;
  int wifi_len = 0;
  int pyld_eth_len = 0;
  int check;
  u_int64_t time;
  u_int16_t ip_offset = 0, ip_len;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0, recheck_type;
  /*u_int32_t label;*/

  /* counters */
  u_int8_t vlan_packet = 0;

  /* Increment raw packet counter */
  workflow->stats.raw_packet_count++;

  /* setting time in millisecondes */
  time = ((uint64_t)header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
  /* safety check */
  if (workflow->last_time > time)
  {
    /* printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time); */
    time = workflow->last_time;
  }
  /* update last time value */
  workflow->last_time = time;

  /*** check Data Link type ***/
  int datalink_type;

  // #ifdef USE_DPDK
  //   datalink_type = DLT_EN10MB;
  // #else
  datalink_type = (int)pcap_datalink(workflow->pcap_handle);
  // #endif
datalink_check:
  switch (datalink_type)
  {
  case DLT_NULL:
    if (ntohl(*((u_int32_t *)&packet[eth_offset])) == 2)
      type = ETH_P_IP;
    else
      type = ETH_P_IPV6;

    ip_offset = 4 + eth_offset;
    break;

    /* Cisco PPP in HDLC-like framing - 50 */
  case DLT_PPP_SERIAL:
    chdlc = (struct ndpi_chdlc *)&packet[eth_offset];
    ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* Cisco PPP - 9 or 104 */
  case DLT_C_HDLC:
  case DLT_PPP:
    chdlc = (struct ndpi_chdlc *)&packet[eth_offset];
    ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* IEEE 802.3 Ethernet - 1 */
  case DLT_EN10MB:
    ethernet = (struct ndpi_ethhdr *)&packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    /*h_proto -> data length (<= 1500) or type ID proto (>=1536) */
    check = ntohs(ethernet->h_proto);
    // In order to allow some frames using Ethernet v2 framing and some using the original version of 802.3 framing to be used on the same Ethernet segment, EtherType values must be greater than or equal to 1536 (0x0600).
    // That value was chosen because the maximum length of the payload field of an Ethernet 802.3 frame is 1500 octets (0x05DC).
    // Thus if the field's value is greater than or equal to 1536, the frame must be an Ethernet v2 frame, with that field being a type field.[10] If it's less than or equal to 1500, it must be an IEEE 802.3 frame, with that field being a length field.
    // Values between 1500 and 1536, exclusive, are undefined.
    if (check <= 1500)
      pyld_eth_len = check;
    else if (check >= 1536)
      type = check;

    if (pyld_eth_len != 0)
    {
      llc = (struct ndpi_llc_header_snap *)(&packet[ip_offset]);
      /* check for LLC layer with SNAP extension */
      // By examining the 802.2 LLC header, it is possible to determine whether it is followed by a SNAP header.
      // The LLC header includes two eight-bit address fields, called service access points (SAPs) in OSI terminology;
      // when both source and destination SAP are set to the value 0xAA, the LLC header is followed by a SNAP header.
      // The SNAP header allows EtherType values to be used with all IEEE 802 protocols, as well as supporting private protocol ID spaces.
      if (llc->dsap == SNAP || llc->ssap == SNAP)
      {
        // The SNAP header consists of a 3-octet IEEE organizationally unique identifier (OUI) followed by a 2-octet protocol ID.
        // If the OUI is hexadecimal 000000, the protocol ID is the Ethernet type (EtherType) field value for the protocol running on top of SNAP;
        // if the OUI is an OUI for a particular organization, the protocol ID is a value assigned by that organization to the protocol running on top of SNAP.
        type = llc->snap.proto_ID;
        // 3-octet LLC header + 5-octet SNAP header
        ip_offset += +8;
      }
      /* No SNAP extension - Spanning Tree pkt must be discarded */
      else if (llc->dsap == BSTP || llc->ssap == BSTP)
      {
        goto v4_warning;
      }
    }
    break;

    /* Linux Cooked Capture - 113 */
  case DLT_LINUX_SLL:
    type = (packet[eth_offset + 14] << 8) + packet[eth_offset + 15];
    ip_offset = 16 + eth_offset;
    break;

    /* Radiotap link-layer - 127 */
  case DLT_IEEE802_11_RADIO:
    radiotap = (struct ndpi_radiotap_header *)&packet[eth_offset];
    radio_len = radiotap->len;

    /* Check Bad FCS presence */
    if ((radiotap->flags & BAD_FCS) == BAD_FCS)
    {
      workflow->stats.total_discarded_bytes += header->len;
      return (nproto);
    }

    /* Calculate 802.11 header length (variable) */
    wifi = (struct ndpi_wifi_header *)(packet + eth_offset + radio_len);
    fc = wifi->fc;

    /* check wifi data presence */
    if (FCF_TYPE(fc) == WIFI_DATA)
    {
      if ((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) || (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
        wifi_len = 26; /* + 4 byte fcs */
    }
    else /* no data frames */
      break;

    /* Check ether_type from LLC */
    llc = (struct ndpi_llc_header_snap *)(packet + eth_offset + wifi_len + radio_len);
    if (llc->dsap == SNAP)
      type = ntohs(llc->snap.proto_ID);

    /* Set IP header offset */
    ip_offset = wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap) + eth_offset;
    break;

  case DLT_RAW:
    ip_offset = eth_offset = 0;
    break;

  default:
    /* printf("Unknown datalink %d\n", datalink_type); */
    return (nproto);
  }

ether_type_check:
  recheck_type = 0;

  /* check ether type */
  switch (type)
  {
  case VLAN:
    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF;
    type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3];
    ip_offset += 4;
    vlan_packet = 1;

    // double tagging for 802.1Q
    while ((type == 0x8100) && (ip_offset < header->caplen))
    {
      vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset + 1]) & 0xFFF;
      type = (packet[ip_offset + 2] << 8) + packet[ip_offset + 3];
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case MPLS_UNI:
  case MPLS_MULTI:
    mpls.u32 = *((uint32_t *)&packet[ip_offset]);
    mpls.u32 = ntohl(mpls.u32);
    workflow->stats.mpls_count++;
    type = ETH_P_IP, ip_offset += 4;

    while (!mpls.mpls.s)
    {
      mpls.u32 = *((uint32_t *)&packet[ip_offset]);
      mpls.u32 = ntohl(mpls.u32);
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case PPPoE:
    workflow->stats.pppoe_count++;
    type = ETH_P_IP;
    ip_offset += 8;
    recheck_type = 1;
    break;

  default:
    break;
  }
  if (recheck_type)
    goto ether_type_check;

  workflow->stats.vlan_count += vlan_packet;

iph_check:
  /* Check and set IP header size and total packet length */
  iph = (struct ndpi_iphdr *)&packet[ip_offset];

  /* just work on Ethernet packets that contain IP */
  if (type == ETH_P_IP && header->caplen >= ip_offset)
  {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    // header->caplen is the length of the whole packet before fragmentation
    // header->len is the length of specific portion of the packet after fragmentation
    // so caplen must be bigger than len
    if (header->caplen < header->len)
    {
      static u_int8_t cap_warning_used = 0;
      if (cap_warning_used == 0)
      {
        if (!workflow->prefs.quiet_mode)
          NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
        cap_warning_used = 1;
      }
    }
  }
  if (iph->version == IPVERSION)
  {
    //ihl is the ip header length in words
    ip_len = ((u_int16_t)iph->ihl * 4);
    iph6 = NULL;
    if (iph->protocol == IPPROTO_IPV6)
    {
      // 6to4 embeds an IPv6 packet in the payload portion of an IPv4 packet with protocol type IPPROTO_IPV6.
      // To send an IPv6 packet over an IPv4 network to a 6to4 destination address, an IPv4 header with protocol type 41 is prepended to the IPv6 packet.
      // The IPv4 destination address for the prepended packet header is derived from the IPv6 destination address of the inner packet
      // (which is in the format of a 6to4 address), by extracting the 32 bits immediately following the IPv6 destination address's 2002::/16 prefix.
      // The IPv4 source address in the prepended packet header is the IPv4 address of the host or router which is sending the packet over IPv4.
      // The resulting IPv4 packet is then routed to its IPv4 destination address just like any other IPv4 packet.
      ip_offset += ip_len;
      goto iph_check;
    }

    if ((frag_off & 0x1FFF) != 0)
    {
      //frag_off consists of 3 bits flag(not used bit + DF bit + MF bit) + 13 bit fragment offset
      static u_int8_t ipv4_frags_warning_used = 0;
      workflow->stats.fragmented_count++;
      if (ipv4_frags_warning_used == 0)
      {
        if (!workflow->prefs.quiet_mode)
          NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
        ipv4_frags_warning_used = 1;
      }
      workflow->stats.total_discarded_bytes += header->len;
      return (nproto);
    }
  }
  else if (iph->version == 6)
  {
    iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    //un1_nxt -> next header in ipv6 header acts as protocol portion in ipv4 header
    proto = iph6->ip6_hdr.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ipv6hdr);

    if (proto == IPPROTO_DSTOPTS /* IPv6 destination option */)
    {
      u_int8_t *options = (u_int8_t *)&packet[ip_offset + ip_len];
      //options[0]
      proto = options[0];
      //
      ip_len += 8 * (options[1] + 1);
    }

    iph = NULL;
  }
  else
  {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if (ipv4_warning_used == 0)
    {
      if (!workflow->prefs.quiet_mode)
        NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }
    workflow->stats.total_discarded_bytes += header->len;
    return (nproto);
  }
  // if(workflow->prefs.decode_tunnels && (proto == IPPROTO_UDP)) {
  //   struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
  //   u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

  //   if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
  //     /* Check if it's GTPv1 */
  //     u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
  //     u_int8_t flags = packet[offset];
  //     u_int8_t message_type = packet[offset+1];

  //     tunnel_type = ndpi_gtp_tunnel;

  //     if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
  //  (message_type == 0xFF /* T-PDU */)) {

  // ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8; /* GTPv1 header len */
  // if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
  // if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
  // if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

  // iph = (struct ndpi_iphdr *) &packet[ip_offset];

  // if(iph->version != IPVERSION) {
  //   // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)workflow->stats.raw_packet_count);
  //   goto v4_warning;
  // }
  //     }
  //   } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
  //     /* https://en.wikipedia.org/wiki/TZSP */
  //     u_int offset           = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
  //     u_int8_t version       = packet[offset];
  //     u_int8_t ts_type       = packet[offset+1];
  //     u_int16_t encapsulates = ntohs(*((u_int16_t*)&packet[offset+2]));

  //     tunnel_type = ndpi_tzsp_tunnel;

  //     if((version == 1) && (ts_type == 0) && (encapsulates == 1)) {
  // u_int8_t stop = 0;

  // offset += 4;

  // while((!stop) && (offset < header->caplen)) {
  //   u_int8_t tag_type = packet[offset];
  //   u_int8_t tag_len;

  //   switch(tag_type) {
  //   case 0: /* PADDING Tag */
  //     tag_len = 1;
  //     break;
  //   case 1: /* END Tag */
  //     tag_len = 1, stop = 1;
  //     break;
  //   default:
  //     tag_len = packet[offset+1];
  //     break;
  //   }

  //   offset += tag_len;

  //   if(offset >= header->caplen)
  //     return(nproto); /* Invalid packet */
  //   else {
  //     eth_offset = offset;
  //     goto datalink_check;
  //   }
  // }
  //     }
  //   } else if(sport == NDPI_CAPWAP_DATA_PORT) {
  //     /* We dissect ONLY CAPWAP traffic */
  //     u_int offset           = ip_offset+ip_len+sizeof(struct ndpi_udphdr);

  //     if((offset+40) < header->caplen) {
  // u_int16_t msg_len = packet[offset+1] >> 1;

  // offset += msg_len;

  // if(packet[offset] == 0x02) {
  //   /* IEEE 802.11 Data */

  //   offset += 24;
  //   /* LLC header is 8 bytes */
  //   type = ntohs((u_int16_t)*((u_int16_t*)&packet[offset+6]));

  //   ip_offset = offset + 8;

  //   tunnel_type = ndpi_capwap_tunnel;
  //   goto iph_check;
  // }
  //     }
  //   }
  // }

  /* process the packet */
  return (packet_processing(workflow, time, vlan_id, tunnel_type, iph, iph6,
                            ip_offset, header->caplen - ip_offset,
                            header->caplen, header, packet, header->ts));
}



void ndpi_free_flow_data_analysis(struct ndpi_flow_info *flow)
{
  if (flow->iat_c_to_s)
    ndpi_free_data_analysis(flow->iat_c_to_s);
  if (flow->iat_s_to_c)
    ndpi_free_data_analysis(flow->iat_s_to_c);

  if (flow->pktlen_c_to_s)
    ndpi_free_data_analysis(flow->pktlen_c_to_s);
  if (flow->pktlen_s_to_c)
    ndpi_free_data_analysis(flow->pktlen_s_to_c);

  if (flow->iat_flow)
    ndpi_free_data_analysis(flow->iat_flow);
}

/* ***************************************************** */

void ndpi_flow_info_freer(void *node)
{
  struct ndpi_flow_info *flow = (struct ndpi_flow_info *)node;

  ndpi_free_flow_info_half(flow);

  ndpi_free_flow_data_analysis(flow);

  ndpi_free(flow);
}

/* ***************************************************/
/**
 * @brief free wrapper function
 */
static void free_wrapper(void *freeable) {
  free(freeable);
}
/* ***************************************************** */

static uint16_t ndpi_get_proto_id(struct ndpi_detection_module_struct *ndpi_mod, const char *name) {
  uint16_t proto_id;
  char *e;
  unsigned long p = strtol(name,&e,0);
  ndpi_proto_defaults_t *proto_defaults = ndpi_get_proto_defaults(ndpi_mod);

  if(e && !*e) {
    if(p < NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS &&
       proto_defaults[p].protoName) return (uint16_t)p;
    return NDPI_PROTOCOL_UNKNOWN;
  }

  for(proto_id=NDPI_PROTOCOL_UNKNOWN; proto_id < NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS; proto_id++) {
    if(proto_defaults[proto_id].protoName &&
       !strcasecmp(proto_defaults[proto_id].protoName,name))
      return proto_id;
  }
  return NDPI_PROTOCOL_UNKNOWN;
}

/* ***************************************************** */

/* ***************************************************** */
void ndpi_workflow_free(struct ndpi_workflow *workflow)
{
  u_int i;

  for (i = 0; i < workflow->prefs.num_roots; i++)
    ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);

  ndpi_exit_detection_module(workflow->ndpi_struct);
  free(workflow->ndpi_flows_root);
  free(workflow);
}

/* ***************************************************** */
/* ***************************************************** */

static NDPI_PROTOCOL_BITMASK debug_bitmask;
static char _proto_delim[] = " \t,:;";
static int parse_debug_proto(struct ndpi_detection_module_struct *ndpi_mod, char *str) {
  char *n;
  uint16_t proto;
  char op=1;
  for(n = strtok(str,_proto_delim); n && *n; n = strtok(NULL,_proto_delim)) {
    if(*n == '-') {
      op = 0;
      n++;
    } else if(*n == '+') {
      op = 1;
      n++;
    }
    if(!strcmp(n,"all")) {
      if(op)
	NDPI_BITMASK_SET_ALL(debug_bitmask);
      else
	NDPI_BITMASK_RESET(debug_bitmask);
      continue;
    }
    proto = ndpi_get_proto_id(ndpi_mod, n);
    if(proto == NDPI_PROTOCOL_UNKNOWN && strcmp(n,"unknown") && strcmp(n,"0")) {
      fprintf(stderr,"Invalid protocol %s\n",n);
      return 1;
    }
    if(op)
      NDPI_BITMASK_ADD(debug_bitmask,proto);
    else
      NDPI_BITMASK_DEL(debug_bitmask,proto);
  }
  return 0;
}

/* ***************************************************** */

extern char *_debug_protocols;
static int _debug_protocols_ok = 0;
struct ndpi_workflow *ndpi_workflow_init(const struct ndpi_workflow_prefs *prefs,
                                         pcap_t *pcap_handle)
{
  struct ndpi_detection_module_struct *module;
  struct ndpi_workflow *workflow;

  set_ndpi_malloc(malloc_wrapper), set_ndpi_free(free_wrapper);
  set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

  /* TODO: just needed here to init ndpi malloc wrapper */
  module = ndpi_init_detection_module(ndpi_no_prefs);

  if (module == NULL)
  {
    NDPI_LOG(0, NULL, NDPI_LOG_ERROR, "global structure initialization failed\n");
    exit(-1);
  }

  workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));
  if (workflow == NULL)
  {
    NDPI_LOG(0, NULL, NDPI_LOG_ERROR, "global structure initialization failed\n");
    ndpi_free(module);
    exit(-1);
  }

  workflow->pcap_handle = pcap_handle;
  workflow->prefs = *prefs;
  workflow->ndpi_struct = module;

  ndpi_set_log_level(module, nDPI_LogLevel);

  if (_debug_protocols != NULL && !_debug_protocols_ok)
  {
    if (parse_debug_proto(module, _debug_protocols))
      exit(-1);
    _debug_protocols_ok = 1;
  }

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  NDPI_BITMASK_RESET(module->debug_bitmask);

  if (_debug_protocols_ok)
    module->debug_bitmask = debug_bitmask;
#endif

  workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));

  return workflow;
}