// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define page_size (4096)

typedef struct block_meta block_meta;

block_meta *head;

size_t padding(size_t size)
{
	if (size % 8 != 0)
		return size + 8 - (size % 8);
	return size;
}
block_meta *find_best_block(size_t size)
{
	//find the best block where to allocate memory
	block_meta *best_block = NULL;
	block_meta *auxx = head; // saving the head

	while (auxx != NULL) {
		if (auxx->size >= size && best_block == NULL && auxx->status == STATUS_FREE)
			best_block = auxx;

		else if (best_block && auxx->size >= size && best_block->size > auxx->size && auxx->status == STATUS_FREE)
			best_block = auxx;

		auxx = auxx->next;
	}
	return best_block;
}

void split(size_t size, block_meta *best_block)
{
	if (best_block->size - size >= (sizeof(block_meta) + 1)) {
		block_meta *block_split_other_part = (void *)best_block + size + sizeof(block_meta);

		block_split_other_part->size = best_block->size - size - sizeof(block_meta);
		block_split_other_part->status = STATUS_FREE;
		block_split_other_part->next = best_block->next;
		block_split_other_part->prev = best_block;
		best_block->size = size;

		if (best_block->next)
			best_block->next->prev = block_split_other_part;

		best_block->next = block_split_other_part;
	}
	best_block->status = STATUS_ALLOC;
}
block_meta *get_last_block(block_meta *head)
{
	while (head != NULL && head->next != NULL)
		head = head->next;
	return head;
}
block_meta *extend_last_block(block_meta *head, size_t size)
{
	block_meta *last_block = get_last_block(head);
	block_meta *expandable = NULL;

	if (head != NULL && last_block != NULL) {
		if (last_block->status == STATUS_FREE) {
			last_block->status = STATUS_ALLOC;

			expandable = sbrk(size - last_block->size);

			DIE(expandable == (void *)-1, "Extennd_last_block failed at sbrk case");

			last_block->size = size;

			return last_block;
		}
		return NULL;
	}
	return NULL;
}

void coalesce(void)
{
	// unite two consecutive free memory blocks
	block_meta *current_block = head;

	while (current_block != get_last_block(current_block) && current_block && get_last_block(current_block)) {
		if (current_block->next && current_block->status == STATUS_FREE && current_block->next->status == STATUS_FREE) {
			current_block->size = current_block->size + current_block->next->size + sizeof(struct block_meta);
			if (current_block->next->next)
				current_block->next->next->prev = current_block;
			current_block->next = current_block->next->next;
		} else {
			current_block = current_block->next;
		}
	}
}

void *os_malloc(size_t size)
{
	block_meta *best_block = NULL;
	block_meta *new_block = NULL;
	block_meta *extended_last_block;
	block_meta *expendable;

	if (size == 0)
		return NULL;

	size = padding(size);
	if (size + sizeof(struct block_meta) < MMAP_THRESHOLD) {
		if (head == NULL) { // Prealloc in sbrk case
			head = sbrk(MMAP_THRESHOLD);
			DIE(head == (void *)-1, "Prealoc failed at sbrk case");

			head->size = MMAP_THRESHOLD - sizeof(struct block_meta);
			head->status = STATUS_FREE;
			head->next = NULL;
			head->prev = NULL;
		}

		best_block = find_best_block(size);

		if (best_block != NULL) {
			split(size, best_block);
			coalesce();
			return (void *)(best_block + 1);
		}
			extended_last_block = extend_last_block(head, size);

			if (extended_last_block != NULL)
				return (void *)(extended_last_block + 1);

			new_block = sbrk(size + sizeof(block_meta));
			DIE(new_block == (void *)-1, "New block failed at sbrk case");

			new_block->status = STATUS_ALLOC;
			new_block->size = size;
			new_block->next = NULL;
			expendable = get_last_block(head);
			new_block->prev = expendable;
			expendable->next = new_block;

			return (void *)(new_block + 1);
	}

	new_block = (block_meta *)mmap(NULL, size + sizeof(block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	new_block->status = STATUS_MAPPED;
	new_block->size = size;
	new_block->next = NULL;
	new_block->prev = NULL;
	return (void *)(new_block + 1);
}

void os_free(void *ptr)
{
	block_meta *block_ptr = (block_meta *)(ptr - sizeof(struct block_meta));
	int munmap_status;

	if (ptr != NULL) {
		if (block_ptr->status == STATUS_MAPPED) {
			munmap_status = munmap(ptr - sizeof(block_meta), block_ptr->size + sizeof(block_meta));
			DIE(munmap_status == -1, "Free block failed at Mapped case");
		} else {
			block_ptr->status = STATUS_FREE;

			coalesce();
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	block_meta *best_block = NULL;
	block_meta *new_block = NULL;
	block_meta *extended_last_block;
	block_meta *expendable;

	size *= nmemb;

	if (size == 0 || nmemb == 0)
		return NULL;

	size = padding(size);
	if ((int)(size + sizeof(struct block_meta)) <= getpagesize()) {
		if (head == NULL) { // Prealloc in sbrk case
			head = sbrk(MMAP_THRESHOLD);

			DIE(head == (void *)-1, "Prealoc failed at sbrk case");

			head->size = MMAP_THRESHOLD - sizeof(struct block_meta);
			head->status = STATUS_FREE;
			head->next = NULL;
			head->prev = NULL;
			memset(head + 1, 0, head->size);
		}

		best_block = find_best_block(size);

		if (best_block != NULL) {
			split(size, best_block);
			coalesce();
			memset(best_block + 1, 0, best_block->size);
			return (void *)(best_block + 1);
		}
			extended_last_block = extend_last_block(head, size);

			if (extended_last_block != NULL) {
				memset(extended_last_block + 1, 0, extended_last_block->size);
				return (void *)(extended_last_block + 1);
			}

			new_block = sbrk(size + sizeof(block_meta));
			DIE(new_block == (void *)-1, "New block failed at sbrk case");

			new_block->status = STATUS_ALLOC;
			new_block->size = size;
			new_block->next = NULL;
			expendable = get_last_block(head);
			new_block->prev = expendable;
			expendable->next = new_block;

			memset(new_block + 1, 0, new_block->size);
			return (void *)(new_block + 1);
	}

	new_block = (block_meta *)mmap(NULL, size + sizeof(block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	new_block->status = STATUS_MAPPED;
	new_block->size = size;
	new_block->next = NULL;
	new_block->prev = NULL;

	memset(new_block + 1, 0, new_block->size);
	return (void *)(new_block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	block_meta *block_ptr = (block_meta *)(ptr)-1;
	block_meta *new_block_realloc = NULL;

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	size = padding(size);
	if (ptr == NULL)
		return os_malloc(size);

	if (block_ptr->status == STATUS_FREE)
		return NULL;

	if (block_ptr->status == STATUS_MAPPED) {
		new_block_realloc = (block_meta *)(os_malloc(size) - sizeof(struct block_meta));

		if (size > block_ptr->size) {
			memcpy(new_block_realloc + 1, ptr, block_ptr->size);
			os_free(ptr);
		} else if (size < block_ptr->size) {
			memcpy(new_block_realloc + 1, ptr, size);
			os_free(ptr);
		}
		return (void *)(new_block_realloc + 1);
	} else if (block_ptr->status == STATUS_ALLOC) {
		if (size < block_ptr->size) {
			split(size, block_ptr);
			coalesce();
			return (void *)(block_ptr + 1);
		} else if (size == block_ptr->size) {
			return (void *)ptr;
		} else if (size > block_ptr->size) {
			coalesce();
			if (block_ptr->next && block_ptr->next->status == STATUS_FREE) {
				if (block_ptr->size + block_ptr->next->size + sizeof(struct block_meta) >= size) {
					block_ptr->status = STATUS_FREE;

					coalesce();
					split(size, block_ptr);
					coalesce();

				return (void *)(block_ptr + 1);
				}
			} else if (block_ptr->next && block_ptr->next->status != STATUS_FREE) {
				block_ptr->status = STATUS_FREE;
				coalesce();
				new_block_realloc = (block_meta *)(os_malloc(size) - sizeof(struct block_meta));

				memcpy(new_block_realloc + 1, ptr, block_ptr->size);

				return (void *)(new_block_realloc + 1);
			}
		}
	}

	return NULL;
}
