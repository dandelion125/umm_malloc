/* ----------------------------------------------------------------------------
 * umm_malloc.c - a memory allocator for embedded systems (microcontrollers)
 *
 * See LICENSE for copyright notice
 * See README.md for acknowledgements and description of internals
 * ----------------------------------------------------------------------------
 *
 * R.Hempel 2007-09-22 - Original
 * R.Hempel 2008-12-11 - Added MIT License biolerplate
 *                     - realloc() now looks to see if previous block is free
 *                     - made common operations functions
 * R.Hempel 2009-03-02 - Added macros to disable tasking
 *                     - Added function to dump heap and check for valid free
 *                        pointer
 * R.Hempel 2009-03-09 - Changed name to umm_malloc to avoid conflicts with
 *                        the mm_malloc() library functions
 *                     - Added some test code to assimilate a free block
 *                        with the very block if possible. Complicated and
 *                        not worth the grief.
 * D.Frank 2014-04-02  - Fixed heap configuration when UMM_TEST_MAIN is NOT set,
 *                        added user-dependent configuration file umm_malloc_cfg.h
 * R.Hempel 2016-12-04 - Add support for Unity test framework
 *                     - Reorganize source files to avoid redundant content
 *                     - Move integrity and poison checking to separate file
 * R.Hempel 2017-12-29 - Fix bug in realloc when requesting a new block that
 *                        results in OOM error - see Issue 11
 * ----------------------------------------------------------------------------
 */

#define DBGLOG_LEVEL 0
#define DBGLOG_FUNCTION
#include "dbglog/dbglog.h"

#include "umm_malloc.h"

#include "umm_malloc_cfg.h"   /* user-dependent */

// Disable 'warning C4706: assignment within conditional expression'
#pragma warning(push)
#pragma warning( disable : 4706)

// We define these intrinsic functions ourselves to so we can remove the 
// standard library dependency
static void * __cdecl memcpy(
    void* pvDst,
    void const* pvSrc,
    unsigned __int64 cbSize);

static void * __cdecl memset(
    void* pvDst,
    int iValue,
    unsigned __int64 cbSize);

#pragma function(memcpy)
#pragma function(memset)

static void * __cdecl memcpy(void* pvDst,
    void const* pvSrc,
    unsigned __int64 cbSize)
{
    unsigned char *pcSrc = NULL;
    unsigned char *pcDst = NULL;
    unsigned __int64 *pqwSrc = (unsigned __int64 *)pvSrc;
    unsigned __int64 *pqwDst = (unsigned __int64 *)pvDst;
    unsigned __int64 i;

    if ((NULL == pvDst)
        || (NULL == pvSrc)
        || (0 == cbSize))
    {
        // Invalid parameters
        return NULL;
    }

    // Copy bytes in unsigned __int64 increments to make things a bit faster
    for (i = 0; i < (cbSize / sizeof(unsigned __int64)); i++)
    {
        pqwDst[i] = pqwSrc[i];
    }

    // Copy the remaining bytes as regular chars
    pcSrc = (unsigned char *)((unsigned __int64)pvSrc + i * sizeof(unsigned __int64));
    pcDst = (unsigned char *)((unsigned __int64)pvDst + i * sizeof(unsigned __int64));
    for (i = 0; i < (cbSize % sizeof(unsigned __int64)); i++)
    {
        pcDst[i] = pcSrc[i];
    }

    return pvDst;
}

static void * __cdecl memset(void* pvDst,
    int iValue,
    unsigned __int64 cbSize)
{
    unsigned char ucValue = (unsigned char)iValue;
    unsigned char *pucDst = NULL;
    unsigned __int64 *pqwDst = (unsigned __int64 *)pvDst;
    unsigned __int64 qwValue = 0;
    unsigned char *pucValue = (unsigned char *)&qwValue;
    unsigned __int64 i = 0;

    if ((NULL == pvDst)
        || (0 == cbSize))
    {
        // Invalid parameters
        return NULL;
    }

    // Build a unsigned __int64 with all bytes set to ucValue
    for (i = 0; i < sizeof(qwValue); i++)
    {
        pucValue[i] = ucValue;
    }

    // Set bytes in unsigned __int64 increments to make things a bit faster
    for (i = 0; i < (cbSize / sizeof(unsigned __int64)); i++)
    {
        pqwDst[i] = qwValue;
    }

    // Set the remaining bytes as regular chars
    pucDst = (unsigned char *)((unsigned __int64)pvDst + i * sizeof(unsigned __int64));
    for (i = 0; i < (cbSize % sizeof(unsigned __int64)); i++)
    {
        pucDst[i] = ucValue;
    }

    return pvDst;
}

/* ------------------------------------------------------------------------- */

#pragma pack(push, 1)

typedef struct umm_ptr_s {
  unsigned short int next;
  unsigned short int prev;
} umm_ptr_t;

typedef struct umm_block_s {
  union {
    umm_ptr_t used;
  } header;
  union {
    umm_ptr_t free;
    unsigned char data[4];
  } body;
} umm_block_t;

#pragma pack(pop)

#define UMM_FREELIST_MASK (0x8000)
#define UMM_BLOCKNO_MASK  (0x7FFF)

/* ------------------------------------------------------------------------- */

#define UMM_NUMBLOCKS(heap) ((heap)->numblocks)

/* ------------------------------------------------------------------------ */

#define UMM_BLOCK(heap, b)  ((heap)->root[b])

#define UMM_NBLOCK(heap, b) (UMM_BLOCK((heap), (b)).header.used.next)
#define UMM_PBLOCK(heap, b) (UMM_BLOCK((heap), (b)).header.used.prev)
#define UMM_NFREE(heap, b)  (UMM_BLOCK((heap), (b)).body.free.next)
#define UMM_PFREE(heap, b)  (UMM_BLOCK((heap), (b)).body.free.prev)
#define UMM_DATA(heap, b)   (UMM_BLOCK((heap), (b)).body.data)

/* -------------------------------------------------------------------------
 * There are additional files that may be included here - normally it's
 * not a good idea to include .c files but in this case it keeps the
 * main umm_malloc file clear and prevents issues with exposing internal
 * data structures to other programs.
 * -------------------------------------------------------------------------
 */

#include "umm_integrity.c"
#include "umm_poison.c"
#include "umm_info.c"

/* ------------------------------------------------------------------------ */

static unsigned short int umm_blocks( unsigned __int64 size ) {

  /*
   * The calculation of the block size is not too difficult, but there are
   * a few little things that we need to be mindful of.
   *
   * When a block removed from the free list, the space used by the free
   * pointers is available for data. That's what the first calculation
   * of size is doing.
   */

  if( size <= (sizeof(((umm_block_t *)0)->body)) )
    return( 1 );

  /*
   * If it's for more than that, then we need to figure out the number of
   * additional whole blocks the size of an umm_block are required.
   */

  size -= ( 1 + (sizeof(((umm_block_t *)0)->body)) );

  return (unsigned short)( 2 + size/(sizeof(umm_block_t)) );
}

/* ------------------------------------------------------------------------ */
/*
 * Split the block `c` into two blocks: `c` and `c + blocks`.
 *
 * - `new_freemask` should be `0` if `c + blocks` used, or `UMM_FREELIST_MASK`
 *   otherwise.
 *
 * Note that free pointers are NOT modified by this function.
 */
static void umm_split_block( umm_heap_t *heap, 
    unsigned short int c,
    unsigned short int blocks,
    unsigned short int new_freemask ) {

  UMM_NBLOCK(heap, c+blocks) = (UMM_NBLOCK(heap, c) & UMM_BLOCKNO_MASK) | new_freemask;
  UMM_PBLOCK(heap, c+blocks) = c;

  UMM_PBLOCK(heap, UMM_NBLOCK(heap, c) & UMM_BLOCKNO_MASK) = (c+blocks);
  UMM_NBLOCK(heap, c)                                = (c+blocks);
}

/* ------------------------------------------------------------------------ */

static void umm_disconnect_from_free_list( umm_heap_t *heap, unsigned short int c ) {
  /* Disconnect this block from the FREE list */

  UMM_NFREE(heap, UMM_PFREE(heap, c)) = UMM_NFREE(heap, c);
  UMM_PFREE(heap, UMM_NFREE(heap, c)) = UMM_PFREE(heap, c);

  /* And clear the free block indicator */

  UMM_NBLOCK(heap, c) &= (~UMM_FREELIST_MASK);
}

/* ------------------------------------------------------------------------
 * The umm_assimilate_up() function assumes that UMM_NBLOCK(c) does NOT
 * have the UMM_FREELIST_MASK bit set!
 */

static void umm_assimilate_up( umm_heap_t *heap, unsigned short int c ) {

  if( UMM_NBLOCK(heap, UMM_NBLOCK(heap, c)) & UMM_FREELIST_MASK ) {
    /*
     * The next block is a free block, so assimilate up and remove it from
     * the free list
     */

    DBGLOG_DEBUG( "Assimilate up to next block, which is FREE\n" );

    /* Disconnect the next block from the FREE list */

    umm_disconnect_from_free_list( heap, UMM_NBLOCK(heap, c) );

    /* Assimilate the next block with this one */

    UMM_PBLOCK(heap, UMM_NBLOCK(heap, UMM_NBLOCK(heap, c)) & UMM_BLOCKNO_MASK) = c;
    UMM_NBLOCK(heap, c) = UMM_NBLOCK(heap, UMM_NBLOCK(heap, c)) & UMM_BLOCKNO_MASK;
  }
}

/* ------------------------------------------------------------------------
 * The umm_assimilate_down() function assumes that UMM_NBLOCK(c) does NOT
 * have the UMM_FREELIST_MASK bit set!
 */

static unsigned short int umm_assimilate_down( umm_heap_t *heap, 
    unsigned short int c, 
    unsigned short int freemask ) {

  UMM_NBLOCK(heap, UMM_PBLOCK(heap, c)) = UMM_NBLOCK(heap, c) | freemask;
  UMM_PBLOCK(heap, UMM_NBLOCK(heap, c)) = UMM_PBLOCK(heap, c);

  return( UMM_PBLOCK(heap, c) );
}

/* ------------------------------------------------------------------------- */

void  umm_init( void *heap_address, unsigned __int64 heap_size, umm_heap_t *heap ) {
  if ((!heap_address) || (0 == heap_size) || (!heap)) {
        return; // Invalid parameters
  }

  /* init heap pointer and size, and memset it to 0 */
  heap->root = (umm_block_t *)heap_address;
  heap->numblocks = (unsigned short)(heap_size / sizeof(umm_block_t));
  memset(heap->root, 0, heap_size);

  /* setup initial blank heap structure */
  {
    /* index of the 0th `umm_block` */
    const unsigned short int block_0th = 0;
    /* index of the 1st `umm_block` */
    const unsigned short int block_1th = 1;
    /* index of the latest `umm_block` */
    const unsigned short int block_last = UMM_NUMBLOCKS(heap) - 1;

    /* setup the 0th `umm_block`, which just points to the 1st */
    UMM_NBLOCK(heap, block_0th) = block_1th;
    UMM_NFREE(heap, block_0th)  = block_1th;
    UMM_PFREE(heap, block_0th)  = block_1th;

    /*
     * Now, we need to set the whole heap space as a huge free block. We should
     * not touch the 0th `umm_block`, since it's special: the 0th `umm_block`
     * is the head of the free block list. It's a part of the heap invariant.
     *
     * See the detailed explanation at the beginning of the file.
     */

    /*
     * 1th `umm_block` has pointers:
     *
     * - next `umm_block`: the latest one
     * - prev `umm_block`: the 0th
     *
     * Plus, it's a free `umm_block`, so we need to apply `UMM_FREELIST_MASK`
     *
     * And it's the last free block, so the next free block is 0.
     */
    UMM_NBLOCK(heap, block_1th) = block_last | UMM_FREELIST_MASK;
    UMM_NFREE(heap, block_1th)  = 0;
    UMM_PBLOCK(heap, block_1th) = block_0th;
    UMM_PFREE(heap, block_1th)  = block_0th;

    /*
     * latest `umm_block` has pointers:
     *
     * - next `umm_block`: 0 (meaning, there are no more `umm_blocks`)
     * - prev `umm_block`: the 1st
     *
     * It's not a free block, so we don't touch NFREE / PFREE at all.
     */
    UMM_NBLOCK(heap, block_last) = 0;
    UMM_PBLOCK(heap, block_last) = block_1th;
  }
}

/* ------------------------------------------------------------------------ */

void umm_free( umm_heap_t *heap, void *ptr ) {

  unsigned short int c;

  if (!heap) {
      return;
  }

  /* If we're being asked to free a NULL pointer, well that's just silly! */

  if( (void *)0 == ptr ) {
    DBGLOG_DEBUG( "free a null pointer -> do nothing\n" );
    return;
  }

  /*
   * FIXME: At some point it might be a good idea to add a check to make sure
   *        that the pointer we're being asked to free up is actually within
   *        the umm_heap!
   *
   * NOTE:  See the new umm_info() function that you can use to see if a ptr is
   *        on the free list!
   */

  /* Protect the critical section... */
  UMM_CRITICAL_ENTRY();

  /* Figure out which block we're in. Note the use of truncated division... */

  c = (unsigned short)(((char *)ptr)-(char *)(&heap->root[0]))/sizeof(umm_block_t);

  DBGLOG_DEBUG( "Freeing block %6i\n", c );

  /* Now let's assimilate this block with the next one if possible. */

  umm_assimilate_up(heap, c);

  /* Then assimilate with the previous block if possible */

  if( UMM_NBLOCK(heap, UMM_PBLOCK(heap, c)) & UMM_FREELIST_MASK ) {

    DBGLOG_DEBUG( "Assimilate down to next block, which is FREE\n" );

    c = umm_assimilate_down(heap, c, UMM_FREELIST_MASK);
  } else {
    /*
     * The previous block is not a free block, so add this one to the head
     * of the free list
     */

    DBGLOG_DEBUG( "Just add to head of free list\n" );

    UMM_PFREE(heap, UMM_NFREE(heap, 0)) = c;
    UMM_NFREE(heap, c)            = UMM_NFREE(heap, 0);
    UMM_PFREE(heap, c)            = 0;
    UMM_NFREE(heap, 0)            = c;

    UMM_NBLOCK(heap, c)          |= UMM_FREELIST_MASK;
  }

  /* Release the critical section... */
  UMM_CRITICAL_EXIT();
}

/* ------------------------------------------------------------------------ */

void *umm_malloc( umm_heap_t *heap, unsigned __int64 size ) {
  unsigned short int blocks;
  unsigned short int blockSize = 0;

  unsigned short int bestSize;
  unsigned short int bestBlock;

  unsigned short int cf;

  if ((!heap) || (0 == size)) {
    return 0;
  }
  
  /* Protect the critical section... */
  UMM_CRITICAL_ENTRY();

  blocks = umm_blocks( size );

  /*
   * Now we can scan through the free list until we find a space that's big
   * enough to hold the number of blocks we need.
   *
   * This part may be customized to be a best-fit, worst-fit, or first-fit
   * algorithm
   */

  cf = UMM_NFREE(heap, 0);

  bestBlock = UMM_NFREE(heap, 0);
  bestSize  = 0x7FFF;

  while( cf ) {
    blockSize = (UMM_NBLOCK(heap, cf) & UMM_BLOCKNO_MASK) - cf;

    DBGLOG_TRACE( "Looking at block %6i size %6i\n", cf, blockSize );

#ifndef UMM_FIRST_FIT
    if( (blockSize >= blocks) && (blockSize < bestSize) ) {
      bestBlock = cf;
      bestSize  = blockSize;
    }
#else
    /* This is the first block that fits! */
    if( (blockSize >= blocks) )
      break;
#endif

    cf = UMM_NFREE(heap, cf);
  }

  if( 0x7FFF != bestSize ) {
    cf        = bestBlock;
    blockSize = bestSize;
  }

  if( UMM_NBLOCK(heap, cf) & UMM_BLOCKNO_MASK && blockSize >= blocks ) {
    /*
     * This is an existing block in the memory heap, we just need to split off
     * what we need, unlink it from the free list and mark it as in use, and
     * link the rest of the block back into the freelist as if it was a new
     * block on the free list...
     */

    if( blockSize == blocks ) {
      /* It's an exact fit and we don't neet to split off a block. */
      DBGLOG_DEBUG( "Allocating %6i blocks starting at %6i - exact\n", blocks, cf );

      /* Disconnect this block from the FREE list */

      umm_disconnect_from_free_list( heap, cf );

    } else {
      /* It's not an exact fit and we need to split off a block. */
      DBGLOG_DEBUG( "Allocating %6i blocks starting at %6i - existing\n", blocks, cf );

      /*
       * split current free block `cf` into two blocks. The first one will be
       * returned to user, so it's not free, and the second one will be free.
       */
      umm_split_block( heap, cf, blocks, UMM_FREELIST_MASK /*new block is free*/ );

      /*
       * `umm_split_block()` does not update the free pointers (it affects
       * only free flags), but effectively we've just moved beginning of the
       * free block from `cf` to `cf + blocks`. So we have to adjust pointers
       * to and from adjacent free blocks.
       */

      /* previous free block */
      UMM_NFREE(heap, UMM_PFREE(heap, cf) ) = cf + blocks;
      UMM_PFREE(heap, cf + blocks ) = UMM_PFREE(heap, cf);

      /* next free block */
      UMM_PFREE(heap, UMM_NFREE(heap, cf) ) = cf + blocks;
      UMM_NFREE(heap, cf + blocks ) = UMM_NFREE(heap, cf);
    }
  } else {
    /* Out of memory */

    DBGLOG_DEBUG(  "Can't allocate %5i blocks\n", blocks );

    /* Release the critical section... */
    UMM_CRITICAL_EXIT();

    return 0;
  }

  /* Release the critical section... */
  UMM_CRITICAL_EXIT();

  return( (void *)&UMM_DATA(heap, cf) );
}

/* ------------------------------------------------------------------------ */

// https://github.com/eokeeffe/C-code/blob/master/C-FAQ/memmove.c
void *memmove(void *dest, void const *src, unsigned __int64 n)
{
    char *dp = dest;
    char const *sp = src;
    if (dp < sp) {
        while (n-- > 0)
            *dp++ = *sp++;
    }
    else {
        dp += n;
        sp += n;
        while (n-- > 0)
            *--dp = *--sp;
    }

    return dest;
}

void *umm_realloc( umm_heap_t *heap, void *ptr, unsigned __int64 size ) {

  unsigned short int blocks;
  unsigned short int blockSize;
  unsigned short int prevBlockSize = 0;
  unsigned short int nextBlockSize = 0;

  unsigned short int c;

  unsigned __int64 curSize;

  if (!heap) {
    return 0;
  }

  /*
  * This code looks after the case of a NULL value for ptr. The ANSI C
  * standard says that if ptr is NULL and size is non-zero, then we've
  * got to work the same a malloc(). If size is also 0, then our version
  * of malloc() returns a NULL pointer, which is OK as far as the ANSI C
  * standard is concerned.
  */

  if (((void *)NULL == ptr)) {
      DBGLOG_DEBUG("realloc the NULL pointer - call malloc()\n");

      return umm_malloc(heap, size);
  }

  /*
  * Now we're sure that we have a non_NULL ptr, but we're not sure what
  * we should do with it. If the size is 0, then the ANSI C standard says that
  * we should operate the same as free.
  */

  if (0 == size) {
      DBGLOG_DEBUG("realloc to 0 size, just free the block\n");

      umm_free(heap, ptr);

      return NULL;
  }

  /*
   * Otherwise we need to actually do a reallocation. A naive approach
   * would be to malloc() a new block of the correct size, copy the old data
   * to the new block, and then free the old block.
   *
   * While this will work, we end up doing a lot of possibly unnecessary
   * copying. So first, let's figure out how many blocks we'll need.
   */

  blocks = umm_blocks( size );

  /* Figure out which block we're in. Note the use of truncated division... */

  c = (unsigned short)(((char *)ptr)-(char *)(&heap->root[0]))/sizeof(umm_block_t);

  /* Figure out how big this block is ... the free bit is not set :-) */

  blockSize = (UMM_NBLOCK(heap, c) - c);

  /* Figure out how many bytes are in this block */

  curSize   = (blockSize*sizeof(umm_block_t))-(sizeof(((umm_block_t *)0)->header));

  /* Protect the critical section... */
  UMM_CRITICAL_ENTRY();

  /* Now figure out if the previous and/or next blocks are free as well as
   * their sizes - this will help us to minimize special code later when we
   * decide if it's possible to use the adjacent blocks.
   *
   * We set prevBlockSize and nextBlockSize to non-zero values ONLY if they
   * are free!
   */

  if ((UMM_NBLOCK(heap, UMM_NBLOCK(heap, c)) & UMM_FREELIST_MASK)) {
      nextBlockSize = (UMM_NBLOCK(heap, UMM_NBLOCK(heap, c)) & UMM_BLOCKNO_MASK)
          - UMM_NBLOCK(heap, c);
  }

  if ((UMM_NBLOCK(heap, UMM_PBLOCK(heap, c)) & UMM_FREELIST_MASK)) {
      prevBlockSize = (c - UMM_PBLOCK(heap, c));
  }

  DBGLOG_DEBUG( "realloc blocks %i blockSize %i nextBlockSize %i prevBlockSize %i\n",
      blocks, blockSize, nextBlockSize, prevBlockSize );

  /*
   * Ok, now that we're here we know how many blocks we want and the current
   * blockSize. The prevBlockSize and nextBlockSize are set and we can figure
   * out the best strategy for the new allocation as follows:
   *
   * 1. If the new block is the same size or smaller than the current block do
   *    nothing.
   * 2. If the next block is free and adding it to the current block gives us
   *    enough memory, assimilate the next block.
   * 3. If the prev block is free and adding it to the current block gives us
   *    enough memory, remove the previous block from the free list, assimilate
   *    it, copy to the new block.
   * 4. If the prev and next blocks are free and adding them to the current
   *    block gives us enough memory, assimilate the next block, remove the
   *    previous block from the free list, assimilate it, copy to the new block.
   * 5. Otherwise try to allocate an entirely new block of memory. If the
   *    allocation works free the old block and return the new pointer. If
   *    the allocation fails, return NULL and leave the old block intact.
   *
   * All that's left to do is decide if the fit was exact or not. If the fit
   * was not exact, then split the memory block so that we use only the requested
   * number of blocks and add what's left to the free list.
   */

    if (blockSize >= blocks) {
        DBGLOG_DEBUG( "realloc the same or smaller size block - %i, do nothing\n", blocks );
        /* This space intentionally left blank */
    } else if ((blockSize + nextBlockSize) >= blocks) {
        DBGLOG_DEBUG( "realloc using next block - %i\n", blocks );
        umm_assimilate_up( heap, c );
        blockSize += nextBlockSize;
    } else if ((prevBlockSize + blockSize) >= blocks) {
        DBGLOG_DEBUG( "realloc using prev block - %i\n", blocks );
        umm_disconnect_from_free_list( heap, UMM_PBLOCK(heap, c) );
        c = umm_assimilate_down( heap, c, 0);
        memmove( (void *)&UMM_DATA(heap, c), ptr, curSize );
        ptr = (void *)&UMM_DATA(heap, c);
        blockSize += prevBlockSize;
    } else if ((prevBlockSize + blockSize + nextBlockSize) >= blocks) {
        DBGLOG_DEBUG( "realloc using prev and next block - %i\n", blocks );
        umm_assimilate_up( heap, c );
        umm_disconnect_from_free_list( heap, UMM_PBLOCK(heap, c) );
        c = umm_assimilate_down(heap, c, 0);
        memmove( (void *)&UMM_DATA(heap, c), ptr, curSize );
        ptr = (void *)&UMM_DATA(heap, c);
        blockSize += (prevBlockSize + nextBlockSize);
    } else {
        DBGLOG_DEBUG( "realloc a completely new block %i\n", blocks );
        void *oldptr = ptr;
        if( (ptr = umm_malloc( heap, size )) ) {
            DBGLOG_DEBUG( "realloc %i to a bigger block %i, copy, and free the old\n", blockSize, blocks );
            memcpy( ptr, oldptr, curSize );
            umm_free( heap, oldptr );
        } else {
            DBGLOG_DEBUG( "realloc %i to a bigger block %i failed - return NULL and leave the old block!\n", blockSize, blocks );
            /* This space intentionally left blank */
        }
        blockSize = blocks;
    }

    /* Now all we need to do is figure out if the block fit exactly or if we
     * need to split and free ...
     */

    if (blockSize > blocks ) {
        DBGLOG_DEBUG( "split and free %i blocks from %i\n", blocks, blockSize );
        umm_split_block( heap, c, blocks, 0 );
        umm_free( heap, (void *)&UMM_DATA(heap, c+blocks) );
    }

    /* Release the critical section... */
    UMM_CRITICAL_EXIT();

    return( ptr );
}

/* ------------------------------------------------------------------------ */

void *umm_calloc( umm_heap_t *heap, unsigned __int64 num, unsigned __int64 item_size ) {
  void *ret;

  ret = umm_malloc( heap, (unsigned __int64)(item_size * num));

  if (ret) {
      memset(ret, 0x00, (unsigned __int64)(item_size * num));
  }

  return ret;
}

/* ------------------------------------------------------------------------ */

#pragma warning(pop)
