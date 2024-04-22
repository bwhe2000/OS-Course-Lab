/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <common/util.h>
#include <common/macro.h>
#include <common/kprint.h>
#include <mm/buddy.h>
int free_count = 0; /*add by bowen*/
int merge_count = 0; /*add by bowen*/

static struct page *get_buddy_chunk(struct phys_mem_pool *pool,
                                    struct page *chunk)
{
        vaddr_t chunk_addr;
        vaddr_t buddy_chunk_addr;
        int order;

        /* Get the address of the chunk. */
        chunk_addr = (vaddr_t)page_to_virt(chunk);
        order = chunk->order;
        /*
         * Calculate the address of the buddy chunk according to the address
         * relationship between buddies.
         */
        buddy_chunk_addr = chunk_addr
                           ^ (1UL << (order + BUDDY_PAGE_SIZE_ORDER));

        /* Check whether the buddy_chunk_addr belongs to pool. */
        if ((buddy_chunk_addr < pool->pool_start_addr)
            || ((buddy_chunk_addr + (1 << order) * BUDDY_PAGE_SIZE)
                > (pool->pool_start_addr + pool->pool_mem_size))) {
                return NULL;
        }

        return virt_to_page((void *)buddy_chunk_addr);
}

/* The most recursion level of split_chunk is decided by the macro of
 * BUDDY_MAX_ORDER. */
static struct page *split_chunk(struct phys_mem_pool *pool, int order,
                                struct page *chunk)
{
        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Recursively put the buddy of current chunk into
         * a suitable free list.
         */
        /* BLANK BEGIN */
        while(chunk->order > order){
                chunk->order --;
                struct page *buddy_chunk = get_buddy_chunk(pool, chunk);
                buddy_chunk->order = chunk->order;
                for(int i = 0; i < (1 << (buddy_chunk->order)); i++){
                        (buddy_chunk + i)->order = buddy_chunk->order;
                }
                list_add(&buddy_chunk->node, &pool->free_lists[buddy_chunk->order].free_list);
                pool->free_lists[buddy_chunk->order].nr_free ++;
                // get_free_mem_size_from_buddy(pool); /* added by bowen*/
        }
        for(int i = 0; i < (1 << (chunk->order)); i++){
                (chunk + i)->order = chunk->order;
        }
        return chunk;
        /* BLANK END */
        /* LAB 2 TODO 1 END */
}

/* The most recursion level of merge_chunk is decided by the macro of
 * BUDDY_MAX_ORDER. */
static struct page *merge_chunk(struct phys_mem_pool *pool, struct page *chunk)
{
        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Recursively merge current chunk with its buddy
         * if possible.
         */
        /* BLANK BEGIN */

        // merge_count += 1;
        // kdebug("merge times: %d\n", merge_count);
        /*added by bowen*/

        struct page *buddy_chunk = get_buddy_chunk(pool, chunk);
        struct page *lower_chunk = NULL;
        while(buddy_chunk != NULL && !buddy_chunk -> allocated && chunk->order + 1 < BUDDY_MAX_ORDER && buddy_chunk->order == chunk->order && buddy_chunk->pool == chunk->pool){
                list_del(&buddy_chunk->node);
                pool->free_lists[buddy_chunk->order].nr_free --;
                if(chunk < buddy_chunk){
                        lower_chunk = chunk;
                }else{
                        lower_chunk = buddy_chunk;
                }
                lower_chunk->order ++;
                for(int i = 0; i < (1 << (lower_chunk -> order)); i++){
                        (lower_chunk + i)->order = lower_chunk->order;
                }
                chunk = lower_chunk;
                buddy_chunk = get_buddy_chunk(pool, chunk);
        }
        return chunk;
        /* BLANK END */
        /* LAB 2 TODO 1 END */
}

/*
 * The layout of a phys_mem_pool:
 * | page_metadata are (an array of struct page) | alignment pad | usable memory
 * |
 *
 * The usable memory: [pool_start_addr, pool_start_addr + pool_mem_size).
 */
void init_buddy(struct phys_mem_pool *pool, struct page *start_page,
                vaddr_t start_addr, unsigned long page_num)
{
        int order;
        int page_idx;
        struct page *page;

        BUG_ON(lock_init(&pool->buddy_lock) != 0);

        /* Init the physical memory pool. */
        pool->pool_start_addr = start_addr;
        pool->page_metadata = start_page;
        pool->pool_mem_size = page_num * BUDDY_PAGE_SIZE;
        /* This field is for unit test only. */
        pool->pool_phys_page_num = page_num;

        /* Init the free lists */
        for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
                pool->free_lists[order].nr_free = 0;
                init_list_head(&(pool->free_lists[order].free_list));
        }

        /* Clear the page_metadata area. */
        memset((char *)start_page, 0, page_num * sizeof(struct page));

        /* Init the page_metadata area. */
        for (page_idx = 0; page_idx < page_num; ++page_idx) {
                page = start_page + page_idx;
                page->allocated = 1;
                page->order = 0;
                page->pool = pool;
        }

        /* Put each physical memory page into the free lists. */
        for (page_idx = 0; page_idx < page_num; ++page_idx) {
                page = start_page + page_idx;
                buddy_free_pages(pool, page);
                check_buddy_pool(pool);

                // int current_free_mem = get_free_mem_size_from_buddy(pool);
                // if(current_free_mem != (page_idx + 1) * BUDDY_PAGE_SIZE){
                //         kdebug("1");
                // }
                /*added by bowen*/
        }
}

struct page *buddy_get_pages(struct phys_mem_pool *pool, int order)
{
        int cur_order;
        struct list_head *free_list;
        struct page *page = NULL;

        if (unlikely(order >= BUDDY_MAX_ORDER)) {
                kwarn("ChCore does not support allocating such too large "
                      "contious physical memory\n");
                return NULL;
        }

        lock(&pool->buddy_lock);

        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Find a chunk that satisfies the order requirement
         * in the free lists, then split it if necessary.
         */
        /* BLANK BEGIN */
        if(pool->free_lists[order].nr_free > 0){
                page = (list_entry(pool->free_lists[order].free_list.next, struct page, node));
                list_del(pool->free_lists[order].free_list.next);
                pool->free_lists[order].nr_free --;
        }else{
                int search_order = order + 1;
                while(search_order < BUDDY_MAX_ORDER){
                        if(pool->free_lists[search_order].nr_free > 0){
                                struct page *splited_chunk = list_entry(pool->free_lists[search_order].free_list.next, struct page, node);
                                list_del(pool->free_lists[search_order].free_list.next);
                                pool->free_lists[search_order].nr_free --;
                                page = split_chunk(pool, order, splited_chunk);
                                break;
                        }
                        search_order ++;
                }
        }
        
        if(page != NULL){
                for(int i = 0; i < (1 << order); i++){
                        (page + i)->allocated = 1;
                }
        }

        // get_free_mem_size_from_buddy(pool); /* added by bowen */

        /* BLANK END */
        /* LAB 2 TODO 1 END */
out:
        unlock(&pool->buddy_lock);
        return page;
}

void buddy_free_pages(struct phys_mem_pool *pool, struct page *page)
{
        int order;
        struct list_head *free_list;

        // free_count += 1;
        // kdebug("free times: %d\n", free_count); 
        // if(free_count == 28880){
        //         kdebug("free times: %d\n", free_count); 
        // }
        /*add by bowen*/
        
        lock(&pool->buddy_lock);

        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Merge the chunk with its buddy and put it into
         * a suitable free list.
         */
        /* BLANK BEGIN */
        page->allocated = 0;
        struct page *merged_chunk = merge_chunk(pool, page);
        list_add(&merged_chunk->node, &pool->free_lists[merged_chunk->order].free_list);
        pool->free_lists[merged_chunk->order].nr_free ++;
        /* BLANK END */
        /* LAB 2 TODO 1 END */

        // get_free_mem_size_from_buddy(pool); /* added by bowen */

        unlock(&pool->buddy_lock);
}

void *page_to_virt(struct page *page)
{
        vaddr_t addr;
        struct phys_mem_pool *pool = page->pool;

        BUG_ON(pool == NULL);

        /* page_idx * BUDDY_PAGE_SIZE + start_addr */
        addr = (page - pool->page_metadata) * BUDDY_PAGE_SIZE
               + pool->pool_start_addr;
        return (void *)addr;
}

struct page *virt_to_page(void *ptr)
{
        struct page *page;
        struct phys_mem_pool *pool = NULL;
        vaddr_t addr = (vaddr_t)ptr;
        int i;

        /* Find the corresponding physical memory pool. */
        for (i = 0; i < physmem_map_num; ++i) {
                if (addr >= global_mem[i].pool_start_addr
                    && addr < global_mem[i].pool_start_addr
                                       + global_mem[i].pool_mem_size) {
                        pool = &global_mem[i];
                        break;
                }
        }

        if (pool == NULL) {
                kdebug("invalid pool in %s", __func__);
                return NULL;
        }

        page = pool->page_metadata
               + (((vaddr_t)addr - pool->pool_start_addr) / BUDDY_PAGE_SIZE);
        return page;
}

unsigned long get_free_mem_size_from_buddy(struct phys_mem_pool *pool)
{
        int order;
        struct free_list *list;
        unsigned long current_order_size;
        unsigned long total_size = 0;

        for (order = 0; order < BUDDY_MAX_ORDER; order++) {
                /* 2^order * 4K */
                current_order_size = BUDDY_PAGE_SIZE * (1 << order);
                list = pool->free_lists + order;
                total_size += list->nr_free * current_order_size;

                /* debug : print info about current order */
                kdebug("buddy memory chunk order: %d, size: 0x%lx, num: %d\n",
                       order,
                       current_order_size,
                       list->nr_free);
        }
        return total_size;
}

void check_buddy_pool(struct phys_mem_pool *pool)
{
        int order;
        struct free_list *list;
        unsigned long current_order_size;
        unsigned long total_size = 0;

        for (order = 0; order < BUDDY_MAX_ORDER; order++) {
                if(pool->free_lists[order].nr_free > 0){
                        struct page *splited_chunk = list_entry(pool->free_lists[order].free_list.next, struct page, node);
                        if(splited_chunk->order != order){
                                kdebug("%d pool order error\n", order);
                        }
                }
        }
        return total_size;
}
