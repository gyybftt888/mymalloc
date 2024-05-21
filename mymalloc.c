/* ref:
https://moss.cs.iit.edu/cs351/slides/slides-malloc.pdf
https://github.com/RAGUL1902/Dynamic-Memory-Allocation-in-C/blob/master/malloc.c
https://github.com/miguelperes/custom-malloc/blob/master/mymemory.c
https://yushuanhsieh.github.io/post/2020-01-19-memory-allocator-implicit-free-list/
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  //for using sbrk() & brk(), not supported in Windows
/*
sbrk(0) -> , sbrk(0) returns the current end address of the data segment, which
typically represents the top of the heap.
brk(ptr) -> takes a pointer as an argument to specify the new end address of the
data segment. If successful, it returns 0; otherwise, it returns -1
*/

#define SUCCESS 0
#define true 1
#define false 0
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MAX_SIZE 10000000
#define BLOCK_SIZE 36  // = 4 + 8 + 8 + 8 + 8

typedef struct free_block {
    int is_free;
    size_t size;
    struct free_block *prev, *next;
    void *ptr;
    char data[1];
} free_block;

free_block *base = NULL;

// search the list till first block be find.
free_block *find_free_block(free_block **last, size_t size) {
    free_block *current = base;
    while (current) {
        if (current->size >= (size + BLOCK_SIZE) && current->is_free) {
            return current;
        }
        *last = current;
        current = current->next;
    }
    return current;
}

// |original block| -> |used block|newblock|
// [  block_size  ]    [   size   ]
void split_block(free_block *block, size_t size) {
    free_block *newblock;
    newblock = block->data + size;
    newblock->is_free = true;
    newblock->size = block->size - size - BLOCK_SIZE;
    newblock->prev = block;
    newblock->next = block->next;
    newblock->ptr = newblock->data;
    block->is_free = false;
    block->size = size;
    block->next = newblock;
    if (newblock->next) newblock->next->prev = newblock;
}

free_block *extend_heap(free_block *last, size_t size) {
    free_block *brk_point;
    brk_point = sbrk(0);
    if (sbrk(BLOCK_SIZE + size) == (void *)-1) return NULL;
    brk_point->size = size;
    brk_point->is_free = false;
    brk_point->prev = NULL;
    brk_point->next = NULL;
    brk_point->ptr = brk_point->data;
    if (last) last->next = brk_point;
    return brk_point;
}

void *myMalloc(size_t __size) {
    if (__size == 0) return NULL;
    free_block *block, *last;
    size_t aligned_size = ALIGN(__size);
    if (base) {
        last = base;
        block = find_free_block(&last, aligned_size);
        if (block) {
            if (block->size - aligned_size > BLOCK_SIZE)
                split_block(block, aligned_size);
            block->is_free = false;
        } else {
            block = extend_heap(last, aligned_size);
            if (!block) return NULL;
        }
        return block->data;
    } else {
        // acquire MAX_SIZE memmory 
        block = extend_heap(base, MAX_SIZE);
        if (!block) return NULL;
        block->is_free = true;              // 04/23 UPDATE
        base = block;
        split_block(block, aligned_size);   // 04/23 UPDATE
    }
    return block->data;
}

// try to merge next free_block
void coalesce(free_block *block) {
    if (block->next && block->next->is_free) {
        block->size += block->next->size + BLOCK_SIZE;
        block->next = block->next->next;
        if (block->next) block->next->prev = block;
    }
}

free_block *get_block_addr(void *ptr) {
    char *tmp = ptr;
    tmp = tmp - BLOCK_SIZE;
    ptr = tmp;
    return (ptr);
}

int is_addr_valid(void *ptr) {
    if (base) {
        if (ptr > base && ptr < sbrk(0)) {
            return (ptr == get_block_addr(ptr)->ptr);
        }
    }
    return 0;
}
void myFree(void *__ptr) {
    if (is_addr_valid(__ptr)) {
        free_block *block = get_block_addr(__ptr);
        block->is_free = 1;
        if (block->prev && block->prev->is_free) {
            coalesce(block->prev);
        }
        if (block->next) {
            coalesce(block);
        } else {
            if (block->prev) {
                block->prev->next = NULL;
            } else {
                base = NULL;
            }
            brk(block);
        }
    }
}

int main() {
    int *a = (int *)myMalloc(sizeof(int) * 10);
    for (int i = 0; i < 10; i++) {
        a[i] = i;
        printf("%d ", a[i]);
    }
    myFree(a);
    brk(get_block_addr(base));
    return SUCCESS;
}