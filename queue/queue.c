/**
 * @file queue.c
 * @author Nikos Fanourakis (4237)
 * @brief Implementation of queue
 * 
 */

#include "queue.h"
#include <assert.h>

queue_t *queue_init()
{
    queue_t *q;
    q = malloc(sizeof(queue_t));
    q->size = 0;
    q->head = NULL;
    q->tail = NULL;
    return q;
}

int queue_is_empty(queue_t *q)
{
    assert(q);
    return (q->size == 0);
}

int enqueue(queue_t *q, double val)
{

    node_t *new_node;

    assert(q);
    new_node = malloc(sizeof(node_t));
    if (new_node == NULL)
    {
        return -1;
    }

    new_node->next = NULL;
    new_node->val = val;
    if(q->size == 0){
        q->head = new_node;
    }else{
        q->tail->next = new_node;
    }
        
    q->tail = new_node;
    q->size++;
    return 0;
}

double queue_peek(queue_t *q)
{
    if (queue_is_empty(q))
    {
        exit(EXIT_FAILURE);
    }

    return q->head->val;
}

double dequeue(queue_t *q)
{

    size_t tmp;
    node_t *del;

    assert(!queue_is_empty(q));
    tmp = queue_peek(q);
    del = q->head;
    q->head = q->head->next;
    q->size--;
    del->next = NULL;
    free(del);

    return tmp;
}

void queue_free(queue_t *q)
{
    assert(queue_is_empty(q));
    q->head = NULL;
    q->tail = NULL;
    free(q);
}