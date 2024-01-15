// SPDX-License-Identifier: BSD-3-Clause

#include "os_threadpool.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <semaphore.h>
#include <stdatomic.h>

#include "log/log.h"
#include "os_list.h"
#include "utils.h"

sem_t sem; // semaphore to control access to a shared resource
// this is used to make the threads wait when the queue is empty
int stop_threads;
extern int total_nodes; // defined in another file

extern int processed_nodes; // track of the number of nodes processed

/* Create a task that would be executed by a thread. */
os_task_t *create_task(void (*action)(void *), void *arg, void (*destroy_arg)(void *))
{
	os_task_t *t;

	t = malloc(sizeof(*t));
	DIE(t == NULL, "malloc");
	t->action = action;           // the function
	t->argument = arg;            // arguments for the function
	t->destroy_arg = destroy_arg; // destroy argument function

	return t;
}

/* Destroy task. */
void destroy_task(os_task_t *t)
{
	if (t->destroy_arg != NULL)
		t->destroy_arg(t->argument);
	free(t);
}

/* Put a new task to threadpool task queue. */
void enqueue_task(os_threadpool_t *tp, os_task_t *t)
{
	// the following vars must not be null
	assert(tp != NULL);
	assert(t != NULL);
	/* TODO: Enqueue task to the shared task queue. Use synchronization. */
	os_list_node_t *head = &(tp->head); // Get the head of the task queue

	pthread_mutex_lock(&(tp->queue_mutex));
	if (head == NULL) { // list is not initiated
		fprintf(stderr, "list of tasks is null\n");
	} else {
		// if list is initiated we can add tasks
		// add at the end; list is circular
		list_add_tail(head, &(t->list));
		sem_post(&sem); // signal that a task is available because was put in queue
							// of tasks
	}

	pthread_mutex_unlock(&(tp->queue_mutex));
}
/*
 * Check if queue is empty.
 * This function should be called in a synchronized manner.
 */
int queue_is_empty(os_threadpool_t *tp)
{
	return list_empty(&tp->head);
}

/*
 * Get a task from threadpool task queue.
 * Block if no task is available.
 * Return NULL if work is complete, i.e. no task will become available,
 * i.e. all threads are going to block.
 */
os_task_t *dequeue_task(os_threadpool_t *tp)
{
	os_task_t *t;

	if (!queue_is_empty(tp)) {
		// Get the task at the end of the queue. The 'list_entry' macro is used to
		// get the structure that contains the list node.
		// This implementation detail was provided on the forum.
		t = list_entry(tp->head.prev, os_task_t, list);
		list_del(tp->head.prev);
		return t;
	}
  // If the queue is empty, return NULL
  // Note: the santinel will always be on the list hence the reason we can't
  // return the list but we return null
	return NULL;
}

/* Loop function for threads */
static void *thread_loop_function(void *arg)
{
	os_threadpool_t *tp = (os_threadpool_t *)arg;

	while (1) {
		os_task_t *t;

		// If there's more than one node,
		if (total_nodes != 1)
			// and queue of tasks is emoty
			if (queue_is_empty(tp))
				sem_wait(&sem); // wait until a task is available or stop_threads is set
		// Lock the queue mutex to ensure thread-safe access to the task queue
		pthread_mutex_lock(&(tp->queue_mutex));
		t = dequeue_task(tp);
		pthread_mutex_unlock(&(tp->queue_mutex));

		// If the dequeued task is NULL, it means there are no more tasks available
		// and can't make more available
		if (t == NULL) {
			// Lock the count mutex to ensure thread-safe access to the stop_threads
			// variable
			pthread_mutex_lock(&(tp->count_mutex));
			stop_threads = 1; // Set stop_threads to 1 to signal all threads to stop
			for (unsigned int i = 0; i < tp->num_threads; ++i)
				sem_post(&sem); // signal all threads to check stop_threads
			pthread_mutex_unlock(&(tp->count_mutex));
			// Break out of the loop as there are no more tasks available
			break;
			// additional verification, kinda useless if everything goes well
			if (stop_threads || total_nodes == 1)
				break;
			continue;
		}
		t->action(t->argument);
		destroy_task(t);
	}

	return NULL;
}

/* Wait completion of all threads. This is to be called by the main thread. */
void wait_for_completion(os_threadpool_t *tp)
{
	/* TODO: Wait for all worker threads. Use synchronization. */
	/* Join all worker threads. */
	for (unsigned int i = 0; i < tp->num_threads; i++)
		// The pthread_join() function is used to make the calling thread wait for
		// the termination of the thread specified by 'tp->threads[i]'.
		// the calling thread will not continue its execution until the joined
		// thread has finished execution.
		pthread_join(tp->threads[i], NULL);
}

/* Create a new threadpool. */
os_threadpool_t *create_threadpool(unsigned int num_threads)
{
	os_threadpool_t *tp = NULL;
	int rc;

	tp = malloc(sizeof(*tp));
	DIE(tp == NULL, "malloc");

	list_init(&tp->head);

	/* TODO: Initialize synchronization data. */

	pthread_mutex_init(&tp->queue_mutex, NULL);
	pthread_mutex_init(&tp->count_mutex, NULL);
	pthread_cond_init(&tp->completion_cond, NULL);
	sem_init(&sem, 0, 0); // initialize the semaphore

	tp->num_threads = num_threads;
	tp->threads = malloc(num_threads * sizeof(*tp->threads));
	DIE(tp->threads == NULL, "malloc");
	for (unsigned int i = 0; i < num_threads; ++i) {
		rc = pthread_create(&tp->threads[i], NULL, &thread_loop_function,
							(void *)tp);
		DIE(rc < 0, "pthread_create");
	}

	return tp;
}

/* Destroy a threadpool. Assume all threads have been joined. */
void destroy_threadpool(os_threadpool_t *tp)
{
	os_list_node_t *n, *p;

/* TODO: Cleanup synchronization data. */
	pthread_mutex_destroy(&(tp->queue_mutex));
	pthread_mutex_destroy(&(tp->count_mutex));
	pthread_cond_destroy(&(tp->completion_cond));
	sem_destroy(&sem); // destroy the semaphore when you're done with it

	list_for_each_safe(n, p, &tp->head) {
		os_task_t *task = list_entry(n, os_task_t, list);

		list_del(n);
		destroy_task(task);
	}

	free(tp->threads);
	free(tp);
}
