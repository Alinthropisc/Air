#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"


#ifdef __cplusplus
extern "C" {
#endif


/// Internal structure of the AVL tree
/// API consumers do not have access to the fields
typedef struct air_avl_tree_s air_avl_tree_t;

// An iterator for traversing a tree
typedef struct air_avl_iter_s air_avl_iter_t;


/**
* Key comparison function
* < 0 if a < b
* > 0 if a > b
* = 0 if a == b
*
* Example: for strings → strcmp
*/
typedef int (*air_avl_cmp_fn)(const void *a, const void *b);


typedef enum AirAvlStatus : int32_t {
    AIR_AVL_OK =  0,
    AIR_AVL_ERR = -1,
    AIR_AVL_KEY_EXISTS =  1,
    AIR_AVL_KEY_MISSING = -2,
    AIR_AVL_EMPTY = -3,
    AIR_AVL_NULL_ARG = -4,
} AirAvlStatus;


/**
* air_avl_create - Create a new AVL tree
*
* @param cmp Key comparison function (not nullptr)
* @return Pointer to the tree, or nullptr on error
*/
[[nodiscard]]
AIR_EXPORT air_avl_tree_t *air_avl_create(air_avl_cmp_fn cmp);

/**
* air_avl_destroy - Free tree memory
*
* @param tree Tree to destroy
*
* IMPORTANT: Keys and values ​​are NOT freed!
* Use air_avl_pick() to retrieve before destroy.
*/

AIR_EXPORT void air_avl_destroy(air_avl_tree_t *tree);

/**
 * air_avl_destroy_full - Free a tree with keys/values
 *
 * @param tree Tree
 * @param free_key Key freeing function (may be nullptr)
 * @param free_val Value freeing function (may be nullptr)
 */
AIR_EXPORT void air_avl_destroy_full(air_avl_tree_t *tree,void (*free_key)(void *),void (*free_val)(void *));


/**
 * air_avl_insert - Insert a key-value pair
 *
 * @param tree Tree
 * @param key Key (the pointer is stored, NOT copied!)
 * @param value Value
 *
 * @return AIR_AVL_OK - success
 * @return AIR_AVL_KEY_EXISTS - the key already exists (> 0)
 * @return AIR_AVL_ERR - memory allocation error
 */
[[nodiscard]]
AIR_EXPORT AirAvlStatus air_avl_insert(air_avl_tree_t *tree,void *key,void *value);

/**
 * air_avl_remove - Delete a record by key
 *
 * @param tree Tree
 * @param key Key to search for
 * @param out_key The original key is written here (may be nullptr)
 * @param out_val The value is written here (may be nullptr)
 *
 * @return AIR_AVL_OK - success
 * @return AIR_AVL_KEY_MISSING - key not found
 */
[[nodiscard]]
AIR_EXPORT AirAvlStatus air_avl_remove(air_avl_tree_t *tree,const void *key,void **out_key,void **out_val);

/**
 * air_avl_get - Get value by key
 *
 * @param tree Tree
 * @param key Key to search for
 * @param out_val Value is written here (can be nullptr)
 *
 * @return AIR_AVL_OK - success
 * @return AIR_AVL_KEY_MISSING - key not found
 */
[[nodiscard]]
AIR_EXPORT AirAvlStatus air_avl_get(air_avl_tree_t *tree,const void *key,void **out_val);

/**
 * air_avl_pick - Pick an arbitrary element
 *
 * Removes and returns any element.
 * Useful for clearing the tree element by element.
 *
 * @param tree Tree
 * @param out_key Key is written here
 * @param out_val Value is written here
 *
 * @return AIR_AVL_OK - success
 * @return AIR_AVL_EMPTY - the tree is empty
 */
[[nodiscard]]
AIR_EXPORT AirAvlStatus air_avl_pick(air_avl_tree_t *tree,void **out_key,void **out_val);


/**
 * air_avl_size - Number of nodes in the tree
 *
 * @param tree Tree (can be nullptr → returns 0)
 * @return Number of nodes
 */
[[nodiscard]]
AIR_EXPORT size_t air_avl_size(const air_avl_tree_t *tree);

/**
 * air_avl_is_empty - Void check
 */
[[nodiscard]]
static inline bool air_avl_is_empty(const air_avl_tree_t *tree)
{
    return air_avl_size(tree) == 0;
}


/**
 * air_avl_iter_create - Create an iterator
 *
 * @param tree The tree to traverse
 * @return The iterator, or nullptr on error
 *
 * IMPORTANT: Do not modify the tree during iteration!
 */
[[nodiscard]]
AIR_EXPORT air_avl_iter_t *air_avl_iter_create(air_avl_tree_t *tree);

/**
 * air_avl_iter_next - Next element (in-order traversal)
 *
 * @param iter Iterator
 * @param out_key The key is written here
 * @param out_val The value is written here
 *
 * @return AIR_AVL_OK - the element has been received
 * @return AIR_AVL_EMPTY - there are no more elements
 */
[[nodiscard]]
AIR_EXPORT AirAvlStatus air_avl_iter_next(air_avl_iter_t  *iter,void **out_key,void **out_val);

/**
 * air_avl_iter_prev - Previous element (reverse in-order)
 */
[[nodiscard]]
AIR_EXPORT AirAvlStatus air_avl_iter_prev(air_avl_iter_t *iter,void **out_key,void **out_val);

/**
 * air_avl_iter_destroy - Free the iterator
 */
AIR_EXPORT void air_avl_iter_destroy(air_avl_iter_t *iter);

/**
 * Convenient macro for tree traversal
 *
 * Example:
 * void *key, *val;
 * AIR_AVL_FOREACH(tree, iter, key, val) {
 * printf("%s\n", (char*)key);
 * }
 */
#define AIR_AVL_FOREACH(tree, iter, key, val)                    \
    for (air_avl_iter_t *(iter) = air_avl_iter_create(tree);     \
         (iter) != nullptr;)                                     \
    for (AirAvlStatus _avl_st =                                  \
             air_avl_iter_next((iter), &(key), &(val));          \
         _avl_st == AIR_AVL_OK                                   \
             ? true                                              \
             : (air_avl_iter_destroy(iter), false);              \
         _avl_st = air_avl_iter_next((iter), &(key), &(val)))


#ifdef __cplusplus
}
#endif


