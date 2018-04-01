/* ----------------------------------------------------------------------------
 * umm_malloc.h - a memory allocator for embedded systems (microcontrollers)
 *
 * See copyright notice in LICENSE.TXT
 * ----------------------------------------------------------------------------
 */

#ifndef UMM_MALLOC_H
#define UMM_MALLOC_H

/* ------------------------------------------------------------------------ */

#pragma pack(push, 1)
struct umm_block_s;
typedef struct umm_block_s umm_block_t;

typedef struct umm_heap_s {
	umm_block_t *root;
	unsigned short int numblocks;
} umm_heap_t;
#pragma pack(pop)

void  umm_init( void *heap_address, unsigned __int64 heap_size, umm_heap_t *heap );
void *umm_malloc( umm_heap_t *heap, unsigned __int64 size );
void *umm_calloc( umm_heap_t *heap, unsigned __int64 num, unsigned __int64 size );
void *umm_realloc( umm_heap_t *heap, void *ptr, unsigned __int64 size );
void  umm_free( umm_heap_t *heap, void *ptr );

/* ------------------------------------------------------------------------ */

#endif /* UMM_MALLOC_H */
