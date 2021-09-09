/**
 * @file queue.h
 * @author Nikos Fanourakis (4237)
 * @brief
 * 
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief A node representing a queue element
 * 
 */
struct node_t
{
  double val;
  struct node_t *next;
};

/**
 * @brief A node representing the whole queue
 * 
 */
struct queue_t
{
  unsigned int size;
  struct node_t *head;
  struct node_t *tail;
};

typedef struct node_t node_t;
typedef struct queue_t queue_t;

/**
 * @brief Initializes the queue
 * 
 * @return queue_t* A pointer to the memory allocated for the queue node
 */
queue_t *queue_init();

/**
 * @brief Checks if the queue is empty
 * 
 * @param q The queue node
 * @return int True when there are no nodes inside the queue
 */
int queue_is_empty(queue_t *q);

/**
 * @brief Adds an element to the end of the queue
 * 
 * @param q The queue pointer
 * @param val The val that the system call was called
 * @return int 0 for success, -1 for failure
 */
int enqueue(queue_t *q, double val);

/**
 * @brief Returns the value of the head queue element
 * 
 * @param q The queue pointer
 * @return double The value of the head element
 */
double queue_peek(queue_t *q);

/**
 * @brief Returns the value of the head queue element, removes it and frees the allocated memory
 * 
 * @param q The queue pointer
 * @return double The value of the head element removed
 */
double dequeue(queue_t *q);

/**
 * @brief Frees queue
 * 
 * @param q The queue pointer
 */
void queue_free(queue_t *q);