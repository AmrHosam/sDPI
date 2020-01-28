char *ndpi_prefix_toa (prefix_t * prefix)
	{
	  return (ndpi_prefix_toa2 (prefix, (char *) NULL));
	}
prefix_t *ndpi_New_Prefix2 (int family, void *dest, int bitlen, prefix_t *prefix)
	{
	  int dynamic_allocated = 0;
	  int default_bitlen = sizeof(struct in_addr) * 8;

	#if defined(PATRICIA_IPV6)
	  if(family == AF_INET6) {
	    default_bitlen = sizeof(struct in6_addr) * 8;
	    if(prefix == NULL) {
	      prefix = (prefix_t*)ndpi_calloc(1, sizeof (prefix_t));
	      dynamic_allocated++;
	    }
	    memcpy (&prefix->add.sin6, dest, sizeof(struct in6_addr));
	  }
	  else
	#endif /* PATRICIA_IPV6 */
	    if(family == AF_INET) {
	      if(prefix == NULL) {
	#ifndef NT
		prefix = (prefix_t*)ndpi_calloc(1, sizeof (prefix4_t));
	#else
		//for some reason, compiler is getting
		//prefix4_t size incorrect on NT
		prefix = ndpi_calloc(1, sizeof (prefix_t)); 
	#endif /* NT */
			
		dynamic_allocated++;
	      }
	      memcpy (&prefix->add.sin, dest, sizeof(struct in_addr));
	    }
	    else {
	      return (NULL);
	    }

	  prefix->bitlen = (bitlen >= 0)? bitlen: default_bitlen;
	  prefix->family = family;
	  prefix->ref_count = 0;
	  if(dynamic_allocated) {
	    prefix->ref_count++;
	  }
	  /* fprintf(stderr, "[C %s, %d]\n", ndpi_prefix_toa (prefix), prefix->ref_count); */
	  return (prefix);
	}
prefix_t *ndpi_Ref_Prefix (prefix_t * prefix)
	{
	  if(prefix == NULL)
	    return (NULL);
	  if(prefix->ref_count == 0) {
	    /* make a copy in case of a static pre
	    fix */
	    return (ndpi_New_Prefix2 (prefix->family, &prefix->add, prefix->bitlen, NULL));
	  }
	  prefix->ref_count++;
	  /* fprintf(stderr, "[A %s, %d]\n", ndpi_prefix_toa (prefix), prefix->ref_count); */
	  return (prefix);
	}
patricia_tree_t * ndpi_New_Patricia (int maxbits)
	{
	  patricia_tree_t *patricia = (patricia_tree_t*)ndpi_calloc(1, sizeof *patricia);

	  patricia->maxbits = maxbits;
	  patricia->head = NULL;
	  patricia->num_active_node = 0;
	  assert((u_int)maxbits <= PATRICIA_MAXBITS); /* XXX */
	  num_active_patricia++;
	  return (patricia);
	}
patricia_node_t *ndpi_patricia_lookup (patricia_tree_t *patricia, prefix_t *prefix)
	{
	  patricia_node_t *node, *new_node, *parent, *glue;
	  u_char *addr, *test_addr;
	  u_int bitlen, check_bit, differ_bit;
	  int i, j;

	  assert (patricia);
	  assert (prefix);
	  assert (prefix->bitlen <= patricia->maxbits);

	  if(patricia->head == NULL) {
	    node = (patricia_node_t*)ndpi_calloc(1, sizeof *node);
	    node->bit = prefix->bitlen;
	    node->prefix = ndpi_Ref_Prefix (prefix);
	    node->parent = NULL;
	    node->l = node->r = NULL;
	    node->data = NULL;
	    patricia->head = node;
	#ifdef PATRICIA_DEBUG
	    fprintf (stderr, "patricia_lookup: new_node #0 %s/%d (head)\n", 
		     ndpi_prefix_toa (prefix), prefix->bitlen);
	#endif /* PATRICIA_DEBUG */
	    patricia->num_active_node++;
	    return (node);
	  }

	  addr = prefix_touchar (prefix);
	  bitlen = prefix->bitlen;
	  node = patricia->head;

	  while (node->bit < bitlen || node->prefix == NULL) {

	    if(node->bit < patricia->maxbits &&
		BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
	      if(node->r == NULL)
		break;
	#ifdef PATRICIA_DEBUG
	      if(node->prefix)
		fprintf (stderr, "patricia_lookup: take right %s/%d\n", 
			 ndpi_prefix_toa (node->prefix), node->prefix->bitlen);
	      else
		fprintf (stderr, "patricia_lookup: take right at %u\n", node->bit);
	#endif /* PATRICIA_DEBUG */
	      node = node->r;
	    }
	    else {
	      if(node->l == NULL)
		break;
	#ifdef PATRICIA_DEBUG
	      if(node->prefix)
		fprintf (stderr, "patricia_lookup: take left %s/%d\n", 
			 ndpi_prefix_toa (node->prefix), node->prefix->bitlen);
	      else
		fprintf (stderr, "patricia_lookup: take left at %u\n", node->bit);
	#endif /* PATRICIA_DEBUG */
	      node = node->l;
	    }

	    assert (node);
	  }

	  assert (node->prefix);
	#ifdef PATRICIA_DEBUG
	  fprintf (stderr, "patricia_lookup: stop at %s/%d\n", 
		   ndpi_prefix_toa (node->prefix), node->prefix->bitlen);
	#endif /* PATRICIA_DEBUG */

	  test_addr = prefix_touchar (node->prefix);
	  /* find the first bit different */
	  check_bit = (node->bit < bitlen)? node->bit: bitlen;
	  differ_bit = 0;
	  for (i = 0; (u_int)i*8 < check_bit; i++) {
	    int r;

	    if((r = (addr[i] ^ test_addr[i])) == 0) {
	      differ_bit = (i + 1) * 8;
	      continue;
	    }
	    /* I know the better way, but for now */
	    for (j = 0; j < 8; j++) {
	      if(BIT_TEST (r, (0x80 >> j)))
		break;
	    }
	    /* must be found */
	    assert (j < 8);
	    differ_bit = i * 8 + j;
	    break;
	  }
	  if(differ_bit > check_bit)
	    differ_bit = check_bit;
	#ifdef PATRICIA_DEBUG
	  fprintf (stderr, "patricia_lookup: differ_bit %d\n", differ_bit);
	#endif /* PATRICIA_DEBUG */

	  parent = node->parent;
	  while (parent && parent->bit >= differ_bit) {
	    node = parent;
	    parent = node->parent;
	#ifdef PATRICIA_DEBUG
	    if(node->prefix)
	      fprintf (stderr, "patricia_lookup: up to %s/%d\n", 
		       ndpi_prefix_toa (node->prefix), node->prefix->bitlen);
	    else
	      fprintf (stderr, "patricia_lookup: up to %u\n", node->bit);
	#endif /* PATRICIA_DEBUG */
	  }

	  if(differ_bit == bitlen && node->bit == bitlen) {
	    if(node->prefix) {
	#ifdef PATRICIA_DEBUG 
	      fprintf (stderr, "patricia_lookup: found %s/%d\n", 
		       ndpi_prefix_toa (node->prefix), node->prefix->bitlen);
	#endif /* PATRICIA_DEBUG */
	      return (node);
	    }
	    node->prefix = ndpi_Ref_Prefix (prefix);
	#ifdef PATRICIA_DEBUG
	    fprintf (stderr, "patricia_lookup: new node #1 %s/%d (glue mod)\n",
		     ndpi_prefix_toa (prefix), prefix->bitlen);
	#endif /* PATRICIA_DEBUG */
	    assert (node->data == NULL);
	    return (node);
	  }

	  new_node = (patricia_node_t*)ndpi_calloc(1, sizeof *new_node);
	  if(!new_node) return NULL;
	  new_node->bit = prefix->bitlen;
	  new_node->prefix = ndpi_Ref_Prefix (prefix);
	  new_node->parent = NULL;
	  new_node->l = new_node->r = NULL;
	  new_node->data = NULL;
	  patricia->num_active_node++;

	  if(node->bit == differ_bit) {
	    new_node->parent = node;
	    if(node->bit < patricia->maxbits &&
		BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
	      assert (node->r == NULL);
	      node->r = new_node;
	    }
	    else {
	      assert (node->l == NULL);
	      node->l = new_node;
	    }
	#ifdef PATRICIA_DEBUG
	    fprintf (stderr, "patricia_lookup: new_node #2 %s/%d (child)\n", 
		     ndpi_prefix_toa (prefix), prefix->bitlen);
	#endif /* PATRICIA_DEBUG */
	    return (new_node);
	  }

	  if(bitlen == differ_bit) {
	    if(bitlen < patricia->maxbits &&
		BIT_TEST (test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07))) {
	      new_node->r = node;
	    }
	    else {
	      new_node->l = node;
	    }
	    new_node->parent = node->parent;
	    if(node->parent == NULL) {
	      assert (patricia->head == node);
	      patricia->head = new_node;
	    }
	    else if(node->parent->r == node) {
	      node->parent->r = new_node;
	    }
	    else {
	      node->parent->l = new_node;
	    }
	    node->parent = new_node;
	#ifdef PATRICIA_DEBUG
	    fprintf (stderr, "patricia_lookup: new_node #3 %s/%d (parent)\n", 
		     ndpi_prefix_toa (prefix), prefix->bitlen);
	#endif /* PATRICIA_DEBUG */
	  }
	  else {
	    glue = (patricia_node_t*)ndpi_calloc(1, sizeof *glue);

	    if(!glue) return(NULL);
	    glue->bit = differ_bit;
	    glue->prefix = NULL;
	    glue->parent = node->parent;
	    glue->data = NULL;
	    patricia->num_active_node++;
	    if(differ_bit < patricia->maxbits &&
		BIT_TEST (addr[differ_bit >> 3], 0x80 >> (differ_bit & 0x07))) {
	      glue->r = new_node;
	      glue->l = node;
	    }
	    else {
	      glue->r = node;
	      glue->l = new_node;
	    }
	    new_node->parent = glue;

	    if(node->parent == NULL) {
	      assert (patricia->head == node);
	      patricia->head = glue;
	    }
	    else if(node->parent->r == node) {
	      node->parent->r = glue;
	    }
	    else {
	      node->parent->l = glue;
	    }
	    node->parent = glue;
	#ifdef PATRICIA_DEBUG
	    fprintf (stderr, "patricia_lookup: new_node #4 %s/%d (glue+node)\n", 
		     ndpi_prefix_toa (prefix), prefix->bitlen);
	#endif /* PATRICIA_DEBUG */
	  }
	  return (new_node);
}
