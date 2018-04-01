/* poisoning (UMM_POISON_CHECK) {{{ */
#if defined(UMM_POISON_CHECK)
#define POISON_BYTE (0xa5)

/*
 * Yields a size of the poison for the block of size `s`.
 * If `s` is 0, returns 0.
 */
static unsigned __int64 poison_size(unsigned __int64 s) {
    return(s ? (UMM_POISON_SIZE_BEFORE +
                sizeof(UMM_POISONED_BLOCK_LEN_TYPE) +
                UMM_POISON_SIZE_AFTER)
             : 0);
}

/*
 * Print memory contents starting from given `ptr`
 */
static void dump_mem ( const unsigned char *ptr, unsigned __int64 len ) {
  while (len--) {
    DBGLOG_ERROR(" 0x%.2x", (unsigned int)(*ptr++));
  }
}

/*
 * Put poison data at given `ptr` and `poison_size`
 */
static void put_poison( unsigned char *ptr, unsigned __int64 poison_size ) {
  memset(ptr, POISON_BYTE, poison_size);
}

/*
 * Check poison data at given `ptr` and `poison_size`. `where` is a pointer to
 * a string, either "before" or "after", meaning, before or after the block.
 *
 * If poison is there, returns 1.
 * Otherwise, prints the appropriate message, and returns 0.
 */
static int check_poison( const unsigned char *ptr, unsigned __int64 poison_size,
    const char *where) {
  unsigned __int64 i;
  int ok = 1;

  for (i = 0; i < poison_size; i++) {
    if (ptr[i] != POISON_BYTE) {
      ok = 0;
      break;
    }
  }

  if (!ok) {
    DBGLOG_ERROR( "No poison %s block at: 0x%lx, actual data:", where, (unsigned long)ptr);
    dump_mem(ptr, poison_size);
    DBGLOG_ERROR( "\n" );
  }

  return ok;
}

/*
 * Check if a block is properly poisoned. Must be called only for non-free
 * blocks.
 */
static int check_poison_block( umm_block_t *pblock ) {
  int ok = 1;

  if (pblock->header.used.next & UMM_FREELIST_MASK) {
    DBGLOG_ERROR( "check_poison_block is called for free block 0x%lx\n", 
		(unsigned long)pblock);
  } else {
    /* the block is used; let's check poison */
    unsigned char *pc = (unsigned char *)pblock->body.data;
    unsigned char *pc_cur;

    pc_cur = pc + sizeof(UMM_POISONED_BLOCK_LEN_TYPE);
    if (!check_poison(pc_cur, UMM_POISON_SIZE_BEFORE, "before")) {
      ok = 0;
      goto clean;
    }

    pc_cur = pc + *((UMM_POISONED_BLOCK_LEN_TYPE *)pc) - UMM_POISON_SIZE_AFTER;
    if (!check_poison(pc_cur, UMM_POISON_SIZE_AFTER, "after")) {
      ok = 0;
      goto clean;
    }
  }

clean:
  return ok;
}

/*
 * Takes a pointer returned by actual allocator function (`umm_malloc` or
 * `umm_realloc`), puts appropriate poison, and returns adjusted pointer that
 * should be returned to the user.
 *
 * `size_w_poison` is a size of the whole block, including a poison.
 */
static void *get_poisoned( unsigned char *ptr, unsigned __int64 size_w_poison ) {
  if (size_w_poison != 0 && ptr != 0) {

    /* Poison beginning and the end of the allocated chunk */
    put_poison(ptr + sizeof(UMM_POISONED_BLOCK_LEN_TYPE),
        UMM_POISON_SIZE_BEFORE);
    put_poison(ptr + size_w_poison - UMM_POISON_SIZE_AFTER,
        UMM_POISON_SIZE_AFTER);

    /* Put exact length of the user's chunk of memory */
    *(UMM_POISONED_BLOCK_LEN_TYPE *)ptr = (UMM_POISONED_BLOCK_LEN_TYPE)size_w_poison;

    /* Return pointer at the first non-poisoned byte */
    return ptr + sizeof(UMM_POISONED_BLOCK_LEN_TYPE) + UMM_POISON_SIZE_BEFORE;
  } else {
    return ptr;
  }
}

/*
 * Takes "poisoned" pointer (i.e. pointer returned from `get_poisoned()`),
 * and checks that the poison of this particular block is still there.
 *
 * Returns un-poisoned pointer, i.e. actual pointer to the allocated memory.
 */
static void *get_unpoisoned( umm_heap_t *heap, unsigned char *ptr ) {
  if (ptr != 0) {
    unsigned short int c;

    ptr -= (sizeof(UMM_POISONED_BLOCK_LEN_TYPE) + UMM_POISON_SIZE_BEFORE);

    /* Figure out which block we're in. Note the use of truncated division... */
    c = (unsigned short)(((char *)ptr)-(char *)(&heap->root[0]))/sizeof(umm_block_t);

    check_poison_block(&UMM_BLOCK(heap, c));
  }

  return ptr;
}

/* }}} */

/* ------------------------------------------------------------------------ */

void *umm_poison_malloc( umm_heap_t *heap, unsigned __int64 size ) {
  void *ret;

  size += poison_size(size);

  ret = umm_malloc( heap, size );

  ret = get_poisoned(ret, size);

  return ret;
}

/* ------------------------------------------------------------------------ */

void *umm_poison_calloc( umm_heap_t *heap, unsigned __int64 num, unsigned __int64 item_size ) {
  void *ret;
  unsigned __int64 size = item_size * num;

  size += poison_size(size);

  ret = umm_malloc(heap, size);
  
  if (ret) {
	  memset(ret, 0x00, size);
  }

  ret = get_poisoned(ret, size);

  return ret;
}

/* ------------------------------------------------------------------------ */

void *umm_poison_realloc( umm_heap_t *heap, void *ptr, unsigned __int64 size ) {
  void *ret;

  ptr = get_unpoisoned(heap, ptr);

  size += poison_size(size);
  ret = umm_realloc( heap, ptr, size );

  ret = get_poisoned(ret, size);

  return ret;
}

/* ------------------------------------------------------------------------ */

void umm_poison_free( umm_heap_t *heap, void *ptr ) {

  ptr = get_unpoisoned(heap, ptr);

  umm_free( heap, ptr );
}

/*
 * Iterates through all blocks in the heap, and checks poison for all used
 * blocks.
 */

int umm_poison_check( umm_heap_t *heap ) {
  int ok = 1;
  unsigned short int cur;
    
  if (!heap) {
    return 0;
  }

  /* Now iterate through the blocks list */
  cur = UMM_NBLOCK(heap, 0) & UMM_BLOCKNO_MASK;

  while( UMM_NBLOCK(heap, cur) & UMM_BLOCKNO_MASK ) {
    if ( !(UMM_NBLOCK(heap, cur) & UMM_FREELIST_MASK) ) {
      /* This is a used block (not free), so, check its poison */
      ok = check_poison_block(&UMM_BLOCK(heap, cur));
      if (!ok){
        break;
      }
    }

    cur = UMM_NBLOCK(heap, cur) & UMM_BLOCKNO_MASK;
  }

  return ok;
}
 
/* ------------------------------------------------------------------------ */

#endif

