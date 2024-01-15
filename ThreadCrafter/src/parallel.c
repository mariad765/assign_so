// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "log/log.h"
#include "os_graph.h"
#include "os_threadpool.h"
#include "utils.h"

///////////////////////////Execution_Time_Paallel_CHECK//////////////////
#define NUM_THREADS 4
struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000};

/*The following comparison is for Test10 just in the example*/
//////////////////////////////For_Parallel///////////////////////////////
/*	──(kali㉿kali)-[~/SO_tema_3/assignment-parallel-graph/tests]
 *	└─$ \time -v ../src/parallel ../tests/in/test10.in
 *	998     Command being timed: "../src/parallel ../tests/in/test10.in"
 *        User time (seconds): 0.10
 *        System time (seconds): 0.04
 *        Percent of CPU this job got: 57%
 *        Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.26
 *        Average shared text size (kbytes): 0
 *        Average unshared data size (kbytes): 0
 *        Average stack size (kbytes): 0
 *        Average total size (kbytes): 0
 *        Maximum resident set size (kbytes): 3240
 *        Average resident set size (kbytes): 0
 *        Major (requiring I/O) page faults: 0
 *        Minor (reclaiming a frame) page faults: 600
 *        Voluntary context switches: 766
 *        Involuntary context switches: 16
 *        Swaps: 0
 *        File system inputs: 0
 *        File system outputs: 0
 *        Socket messages sent: 0
 *        Socket messages received: 0
 *        Signals delivered: 0
 *        Page size (bytes): 4096
 *        Exit status: 0
 *
 *	/////////////////////////////For_Serial//////////////////////////////
 *	─(kali㉿kali)-[~/SO_tema_3/assignment-parallel-graph/tests]
 *	└─$ \time -v ../src/serial ../tests/in/test10.in
 *	998     Command being timed: "../src/serial ../tests/in/test10.in"
 *        User time (seconds): 0.00
 *        System time (seconds): 0.04
 *        Percent of CPU this job got: 4%
 *        Elapsed (wall clock) time (h:mm:ss or m:ss): 0:01.00
 *        Average shared text size (kbytes): 0
 *        Average unshared data size (kbytes): 0
 *        Average stack size (kbytes): 0
 *        Average total size (kbytes): 0
 *        Maximum resident set size (kbytes): 2904
 *        Average resident set size (kbytes): 0
 *        Major (requiring I/O) page faults: 0
 *        Minor (reclaiming a frame) page faults: 523
 *        Voluntary context switches: 584
 *        Involuntary context switches: 1
 *        Swaps: 0
 *        File system inputs: 0
 *        File system outputs: 0
 *        Socket messages sent: 0
 *        Socket messages received: 0
 *        Signals delivered: 0
 *        Page size (bytes): 4096
 *        Exit status: 0
 */
//////////////////////////////////////////////////////////////////////////////////
static int sum;
static os_graph_t *graph;
static os_threadpool_t *tp;
/* TODO: Define graph synchronization mechanisms. */
static pthread_mutex_t sum_mutex;	//	mutex used to
									//	control the access to sum
static pthread_mutex_t graph_mutex;	//	control the access to the graph data structure.
//	so it can be accessed only be a thread at a time
void process_node_wrapper(void *idx_ptr);
	// takes a pointer to an index as an argument because
    // initial function didn't have a pointer as argument and it
    // was required by create task already implemented; a
	// wrapper around the 'process_node' function, allowing it
	// to be used by a thread.
int total_nodes; // total nodes in a conex component including 0 node
int processed_nodes; // all processed nodes

/*	DFS on the graph.
 *	I added an array of integers where each element indicates whether the
 *	node at the corresponding index has been visited or not.
 *	NOTE: this DFS will iterate only over one conex component
 *	That component includes node 0;
 */
void dfs(int idx, int visited[], os_graph_t *graph)
{
	visited[idx] = 1; // mark the current node as visited
	os_node_t *node = graph->nodes[idx];

	for (int i = 0; i < (int)node->num_neighbours; i++) {
		// iterate over all the neighbours
		int neighbour = node->neighbours[i];
		// for each neighbour, if the neighbour has not been visited yet, it
		// *recursively performs a DFS on the neighbour.
		if (!visited[neighbour])
			dfs(neighbour, visited, graph);
	}
}

/*
 * gives number of nodes in a connected component of a graph.
 * DFS starting from a given node to find all
 * reachable nodes.
 */
int count_nodes_in_component(int start_idx, os_graph_t *graph)
{
	int *visited = calloc(graph->num_nodes, sizeof(int)); // vector de vizitati

	dfs(start_idx, visited, graph);
	int count = 0;

	for (int i = 0; i < (int)graph->num_nodes; i++)
		if (visited[i])
			count++;
	free(visited);
	return count;
}

/*
 * The same as the previous function, this will count the nodes but only the
 * processed ones in a componenet of the graph
 */
int count_processed_nodes_in_component(int start_idx, os_graph_t *graph)
{
	int *visited = calloc(graph->num_nodes, sizeof(int));

	dfs(start_idx, visited, graph);
	int count = 0;

	for (int i = 0; i < (int)graph->num_nodes; i++)
		if (visited[i] == 1 && graph->visited[i] != 0)
			count++;
	free(visited);
	return count;
}

static void process_node(unsigned int idx)
{
	// the node from the graph that has that index
	os_node_t *node = graph->nodes[idx];
	/* to check the performance compared to serial implementation*/
	nanosleep(&ts, NULL);

	// lock to make sure sum is counted properly
	pthread_mutex_lock(&sum_mutex);
	// always check the number of processed nodes, this doesnt really help with
	// the parallel implementation.
	processed_nodes = count_processed_nodes_in_component(0, graph);

	// no need to process already processed nodes
	if (graph->visited[idx] == DONE) {
		pthread_mutex_unlock(&sum_mutex);
		return;
	}
	// do the sum
	sum += node->info;
	// mark as processed node
	graph->visited[idx] = DONE;
	// unlock cause sum was changed
	pthread_mutex_unlock(&sum_mutex);
	// make sure node has neighbours
	if (node->num_neighbours == 0)
		return;

	for (int i = 0; i < (int)node->num_neighbours; ++i) {
		// for each neighbour
		// go through thos function
		// process_node function will be in recursion because of how threads work
		pthread_mutex_lock(&graph_mutex);
		unsigned int neighbour_idx = node->neighbours[i];

		if (graph->visited[neighbour_idx] == NOT_VISITED) {
			// take only non-processing/ no processed nodes
			graph->visited[neighbour_idx] = PROCESSING;
			// as nodes go through this process, they are not done yet (their sum
			// hasn;t been added yet)
			unsigned int *idx_ptr =
			malloc(sizeof(unsigned int)); // argument of process_node fun
			*idx_ptr = neighbour_idx;
			os_task_t *task = create_task((void (*)(void *))process_node_wrapper, (void *)idx_ptr,
																		(void (*)(void *))free);
			enqueue_task(tp, task); // add the task created in the queue
		}

		pthread_mutex_unlock(&graph_mutex);
	}
}

void process_node_wrapper(void *arg)
{	unsigned int idx = *(unsigned int *)arg;
	process_node(idx);
}

int main(int argc, char *argv[])
{
	FILE *input_file;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s input_file\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	input_file = fopen(argv[1], "r");
	DIE(input_file == NULL, "fopen");

	graph = create_graph_from_file(input_file);

	/* TODO: Initialize graph synchronization mechanisms. */
	total_nodes = 0;
	total_nodes = count_nodes_in_component(0, graph);
	// fprintf(stderr, "total noduri: %d\n", total_nodes);
	pthread_mutex_init(&sum_mutex, NULL);
	pthread_mutex_init(&graph_mutex, NULL);
	pthread_mutex_init(&sum_mutex, NULL);
	tp = create_threadpool(NUM_THREADS);
	process_node(0);
	wait_for_completion(tp);
	destroy_threadpool(tp);

	printf("%d", sum);

	return 0;
}
