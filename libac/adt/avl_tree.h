/* air — AVL tree public API. C23.
 * Pattern: Opaque Handle — callers see only pointers, never struct internals. */
#pragma once

#include <stddef.h>

typedef struct c_avl_node_s      c_avl_node_t;
typedef struct c_avl_tree_s      c_avl_tree_t;
typedef struct c_avl_iterator_s  c_avl_iterator_t;

[[nodiscard]] c_avl_tree_t *c_avl_create(int (*compare)(const void *, const void *));
void         c_avl_destroy(c_avl_tree_t *t);

int          c_avl_insert(c_avl_tree_t *t, void *key, void *value);
int          c_avl_remove(c_avl_tree_t *t, const void *key, void **rkey, void **rvalue);
[[nodiscard]] int c_avl_get(c_avl_tree_t *t, const void *key, void **value);
[[nodiscard]] int c_avl_size(c_avl_tree_t *t);

[[nodiscard]] c_avl_iterator_t *c_avl_get_iterator(c_avl_tree_t *t);
int          c_avl_iterator_next(c_avl_iterator_t *iter, void **key, void **value);
void         c_avl_iterator_destroy(c_avl_iterator_t *iter);
