# assign_so
This is a collection of assignments


# Assignment 1: [thread_poll_parallel_graph]

## task

### Objectives

- Learn how to design and implement parallel programs
- Gain skills in using synchronization primitives for parallel programs
- Get a better understanding of the POSIX threading and synchronization API
- Gain insight on the differences between serial and parallel programs


### Statement

Implement a generic thread pool, then use it to traverse a graph and compute the sum of the elements contained by the nodes. You will be provided with a serial implementation of the graph traversal and with most of the data structures needed to implement the thread pool. Your job is to write the thread pool routines and then use the thread pool to traverse the graph.

### Implementation and its README can be found in ThreadCrafter dir



# Assignment 2: [mini_shell]

## task

### Objectives
- Learn how shells create new child processes and connect the I/O to the terminal.
- Gain a better understanding of the fork() function wrapper.
- Learn to correctly execute commands written by the user and treat errors.


### Statement

For this assignment you will build a Bash-like shell with minimal functionalities like traversing the file system, running applications, redirecting their output or piping the output from one application into the input of another.

### Implementation and its README can be found in ServerHttp dir

# Assignment 3: [async_web_server_http]

## task

### Objectives
- make a web server that uses the following advanced I/O operations:
- Asynchronous operations on files
- Non-blocking operations on sockets
- Zero-copying
- Multiplexing I/O operations
- The server implements a limited functionality of the HTTP protocol: passing files to clients.


### Statement

The web server will use the multiplexing API to wait for connections from clients - epoll. On the established connections, requests from clients will be received and then responses will be distributed to them.

### Implementation and its README can be found in ServerHttp dir

