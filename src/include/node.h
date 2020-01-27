


#ifndef _NODE_H_
#define _NODE_H_

#include "actypes.h"

/* Forward Declaration */
struct edge;

/* automata node */
typedef struct ac_node
{
  int id; /* Node ID : for debugging purpose */
  short int final; /* 0: no ; 1: yes, it is a final node */
  struct ac_node * failure_node; /* The failure node of this node */
  unsigned short depth; /* depth: distance between this node and the root */

  /* Matched patterns */
  AC_PATTERN_t * matched_patterns; /* Array of matched patterns */
  unsigned short matched_patterns_num; /* Number of matched patterns at this node */
  unsigned short matched_patterns_max; /* Max capacity of allocated memory for matched_patterns */

  /* Outgoing Edges */
  struct edge * outgoing; /* Array of outgoing edges */
  unsigned short outgoing_degree; /* Number of outgoing edges */
  unsigned short outgoing_max; /* Max capacity of allocated memory for outgoing */
} AC_NODE_t;

/* The Edge of the Node */
struct edge
{
  AC_ALPHABET_t alpha; /* Edge alpha */
  struct ac_node * next; /* Target of the edge */
};


AC_NODE_t * node_create            (void);
AC_NODE_t * node_create_next       (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
void        node_register_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * str, u_int8_t is_existing);
void        node_register_outgoing (AC_NODE_t * thiz, AC_NODE_t * next, AC_ALPHABET_t alpha);
AC_NODE_t * node_find_next         (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
AC_NODE_t * node_findbs_next       (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
void        node_release           (AC_NODE_t * thiz, u_int8_t free_pattern);
void        node_assign_id         (AC_NODE_t * thiz);
void        node_sort_edges        (AC_NODE_t * thiz);

#endif