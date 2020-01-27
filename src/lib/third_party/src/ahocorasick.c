#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#define REALLOC_CHUNK_ALLNODES 200

/******************************************************************************
 * FUNCTION: ac_automata_init
 * Initialize automata; allocate memories and set initial values
 * PARAMS:
 * MATCH_CALLBACK mc: call-back function
 * the call-back function will be used to reach the caller on match occurrence
 ******************************************************************************/
AC_AUTOMATA_t * ac_automata_init (MATCH_CALLBACK_f mc)
{
  AC_AUTOMATA_t * thiz = (AC_AUTOMATA_t *)ndpi_malloc(sizeof(AC_AUTOMATA_t));
  memset (thiz, 0, sizeof(AC_AUTOMATA_t));
  thiz->root = node_create ();
  thiz->all_nodes_max = REALLOC_CHUNK_ALLNODES;
  thiz->all_nodes = (AC_NODE_t **) ndpi_malloc (thiz->all_nodes_max*sizeof(AC_NODE_t *));
  thiz->match_callback = mc;
  ac_automata_register_nodeptr (thiz, thiz->root);
  thiz->total_patterns = 0;
  thiz->automata_open = 1;
  return thiz;
}