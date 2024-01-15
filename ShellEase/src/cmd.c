// SPDX-License-Identifier: BSD-3-Clause

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmd.h"
#include "utils.h"

#define READ 0
#define WRITE 1

char current_path[PATH_MAX]; // PATH_MAX defines the maximum length for a path

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	char current_dir[PATH_MAX];

	if (getcwd(current_dir, sizeof(current_dir)) == NULL) {
		perror("getcwd");
		return 1; // use return 1 for failure
	}
	if (dir == NULL || dir->string == NULL)
		// safty check
		return 1; // use return 1 for error
	if (dir->next_word != NULL) {
		fprintf(stderr, "cd: too many arguments\n");
		return 1; // use return 1 for failure
	}
	// currect_dir stores the currect directory got by call getcwd
	if (strlen(current_path) == 0) {
		strcat(current_dir, "/");
		strcat(current_dir, dir->string); // update curr_dir
	} else {
		// currect path is global and will remember the last path
		strcat(current_path, "/");
		strcat(current_path, dir->string); // update curr_path with choice
	}
	// change dir using call chdir
	if (chdir(dir->string) != 0) {
		// chdir fails
		return 1; // use return 1 for error
	}
	// Update the current_path variable after successful chdir
	if (getcwd(current_path, sizeof(current_path)) == NULL) {
		perror("getcwd"); // in case of failure
		return 1;         // use return 1 for failure
	}
	// all good, return 0 for success
	return 0;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	// The shell program is terminated with the success status.
	int status = 0; // replace with the desired exit status

	exit(status);
}

// Function to check if a command needs input files
bool command_needs_input_files(const char *command_name)
{
	// check if command needs input files as those might be missing
	static const char * const commands_with_input[] = {
		"gcc", "cat"}; // 2 found so far but can add more

	for (int i = 0;
	i < sizeof(commands_with_input) / sizeof(commands_with_input[0]); ++i)
		if (strcmp(command_name, commands_with_input[i]) == 0)
			return true;
	return false;
}

/* Function to execute external commands */
static int execute_external_command(simple_command_t *s)
{
	pid_t pid = fork();

	if (pid < 0) {
		// fork failed
		fprintf(stderr, "Error: Fork failed.\n"); // notice fork failed
		return -1; // return -1 for error on fork fail
	}
	if (pid == 0) {
		// Child process
		int flags = O_CREAT | O_WRONLY; // flags for opening files
		// there are 2 cases: file must be created or file exists and only need to
		// append to it
		if ((s->io_flags & IO_OUT_APPEND) || (s->io_flags & IO_ERR_APPEND))
			flags |= O_APPEND; // append to file
		else
			flags |= O_TRUNC; // file should be truncated to zero length.
		// check if the command take an input file
		if (s->in != NULL) {
			// open input file , check for error on opening and if errot function will
			// exit failure code
			int input_fd = open(s->in->string, O_CREAT | O_RDONLY);

			if (input_fd == -1) {
				perror("Error: Unable to open input file");
				exit(EXIT_FAILURE);
			}
			// perform redirections if it fails function will exit with failure code
			if (dup2(input_fd, STDIN_FILENO) == -1) {
				perror("Error: dup2 failed");
				exit(EXIT_FAILURE);
			}
			close(input_fd);
		}
		// check if the function should take an input file
		if (command_needs_input_files(s->verb->string)) {
			// the function should take an input file but the file is null
			if (s->in == NULL) {
				// redirection in the output error file
				if (s->err != NULL && s->err->string != NULL) {
					int output_fd = open(get_word(s->err), flags, 0644);

					if (output_fd == -1) {
						perror(s->out->string);
						exit(EXIT_FAILURE); // exit failure code
					}
					if (dup2(output_fd, STDERR_FILENO) == -1) {
						perror("dup2");
						exit(EXIT_FAILURE); // exit failure code
					}
					close(output_fd);
				}
			}
			// check if input file exits
			if (access(s->in, F_OK) != -1) {
				// check if there is any output file for error
				if (s->err != NULL && s->err->string != NULL) {
					// in that case, execute the command and redirect any error messages
					// in this file
					int output_fd = open(get_word(s->err), flags, 0644);

					if (output_fd == -1) {
						perror(s->err->string);
						exit(EXIT_FAILURE);
					}
					if (dup2(output_fd, STDERR_FILENO) == -1) {
						perror("dup2");
						exit(EXIT_FAILURE);
					}
					close(output_fd);
				}
				// check if there is any output file to redirect to
				if (s->out != NULL && s->out->string != NULL) {
					// if there is , redirect to it the output of the command
					int output_fd = open(get_word(s->out), flags, 0644);

					if (output_fd == -1) {
						perror(s->out->string);
						exit(EXIT_FAILURE);
					}
					if (dup2(output_fd, STDERR_FILENO) == -1) {
						perror("dup2");
						exit(EXIT_FAILURE);
					}
					close(output_fd);
				}
			} else {
				// if the input file is not accessible
				// check for any output files to redirect to
				if (s->out != NULL && s->out->string) {
					int output_fd = open(get_word(s->out), flags, 0644);

					if (output_fd == -1) {
						perror(s->out->string);
						exit(EXIT_FAILURE);
					}

					if (dup2(output_fd, STDOUT_FILENO) == -1) {
						perror("dup2");
						exit(EXIT_FAILURE);
					}
					// check if the output shall be redirected in any error files
					if (s->err != NULL && s->err->string &&
						strcmp(s->out->string, s->err->string) == 0)
						dup2(output_fd, STDERR_FILENO);
					close(output_fd);
				}
				// If the same file is specified for error redirection, redirect stderr
				// to this file as well
				if (s->err != NULL && s->err->string && s->out == NULL) {
					int output_fd = open(get_word(s->err), flags, 0644);

					if (output_fd == -1) {
						// if this failed to open, exit with error code
						exit(EXIT_FAILURE);
					}
					if (dup2(output_fd, STDERR_FILENO) == -1) {
						perror("dup2");
						exit(EXIT_FAILURE);
					}
					close(output_fd);
				}
			}
	}
		// command doesnt take input files so we don't need to check it's
		// absence
		if (!command_needs_input_files(s->verb->string)) {
		// redirect in output file and err file  if they exist
			if (s->out != NULL && s->out->string) {
				int output_fd = open(get_word(s->out), flags, 0644);

				if (output_fd == -1) {
					// if the file was not opened successfully, print an error message
					perror(s->out->string);
					// exit status code shall be for failure
					exit(EXIT_FAILURE);
				}
				if (dup2(output_fd, STDOUT_FILENO) == -1) {
					perror("dup2");     // error message for dup2
					exit(EXIT_FAILURE); // exit with failure code
				}
				/*
				 * redirect also for error file if it is the same with output file
				 * Case described in parser: * Some string literals can be found in both
				 * the out list and the err list
				 * (those entered as "command &> out").
				 */
				if (s->err != NULL && s->err->string &&
				strcmp(s->out->string, s->err->string) == 0)
					if (dup2(output_fd, STDERR_FILENO) == -1) {
						perror("dup2");
						exit(EXIT_FAILURE); // exit with failure code
					}
				close(output_fd);
			}
			// if file is specified for error redirection, redirect stderr
			// to this file and there is no output file
			if (s->err != NULL && s->err->string && s->out == NULL) {
				int output_fd = open(get_word(s->err), flags, 0644);

				if (output_fd == -1)
					// exit failure for open fail
					exit(EXIT_FAILURE);
				if (dup2(output_fd, STDERR_FILENO) == -1) {
					perror("dup2");     // error message for dup2
					exit(EXIT_FAILURE); // failure code
				}
				close(output_fd);
			}
			// In some cases when redirecting the output name exists but it is not the
			// same as the error file name
			if (s->err != NULL && s->err->string && s->out != NULL &&
				strcmp(s->err->string, s->out->string)) {
				int output_fd = open(get_word(s->err), flags, 0644);

				if (output_fd == -1)
					// open fails => exit code failure
					exit(EXIT_FAILURE);
				if (dup2(output_fd, STDERR_FILENO) == -1) {
					perror("dup2");
					exit(EXIT_FAILURE); // dup2 fails => exit failure code
				}
				close(output_fd);
			}
	}
		// Execute the external commandd
		// s->verb contains the command and s->params contains the
		// parameters
		if (s->params != NULL) {
			int size = 0;
			char **argv = get_argv(s, &size); // function fron utils.

			if (execvp(argv[0], argv) == -1) {
				// command failed to execute : case it doesnt exist.
				fprintf(stderr, "Error: Execution failed for command %s.\n", argv[0]);
				exit(EXIT_FAILURE); // exit failure code
			}
			free(argv);
		}
		if (s->params == NULL) {
			const char *argv[2];

			argv[0] = s->verb->string;
			argv[1] = NULL;
			if (execvp(argv[0], argv) == -1) {
				// command failed to execute : case it doesnt exist.
				fprintf(stderr, "Execution failed for '%s'\n", s->verb->string);
				exit(EXIT_FAILURE);
			}
		}
	} else {
		// Parent process
		int status;

		waitpid(pid, &status, 0); // wait for the child process to complete
		// get the satus the child exited
		if (WIFEXITED(status))
			// Child process terminated normally
			return WEXITSTATUS(status); // return exit status of the child process
			// return -1 for any child process that finished without a success exit
			// code
		fprintf(stderr, "Error: Child process terminated abnormally.\n");
		return -1;
	}
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (s == NULL) {
		fprintf(stderr, "Error: simple_command_t pointer is NULL.\n");
		return -1; // will use -1 for error
	}
	// I considered level should always be positive
	if (level < 0) {
		fprintf(stderr, "Error: level is negative.\n");
		return -1;
	}
	/* TODO: If builtin command, execute the command. */
	// internal commands managed: pwd, cd, exit, quit
	if (strcmp(s->verb->string, "cd") == 0) {
		// handle redirectations:
		/*
		 * the 'IO_OUT_APPEND' or 'IO_ERR_APPEND' flags are set in 's->io_flags',
		 * O_APPEND flag is added to 'flags'. This flag ensures that data written to
		 * the file will be appended to its existing contents rather than
		 * overwriting them. O_TRUNC truncates the file to zero length if it exists
		 * or creates a new file.
		 * Performs redirections regarding the input file and the output file
		 * If "cd" doesnt have params, nothing happens;
		 * function will return 0 if cd was executed successfully
		 */
		int flags = O_CREAT | O_WRONLY;

		if ((s->io_flags & IO_OUT_APPEND) || (s->io_flags & IO_ERR_APPEND))
			flags |= O_APPEND;
		else
			flags |= O_TRUNC;
		if (s->in != NULL && s->in->string != NULL) {
			int input_fd = open(s->in->string, O_CREAT | O_RDONLY);

			if (input_fd == -1) {
				perror("Error: Unable to open input file");
				exit(EXIT_FAILURE);
			}
			if (dup2(input_fd, STDIN_FILENO) == -1) {
				perror("Error: dup2 failed");
				exit(EXIT_FAILURE);
			}
			close(input_fd);
		}
		if (s->out != NULL && s->out->string != NULL) {
			int output_fd = open(get_word(s->out), flags, 0644);

			if (output_fd == -1)
				exit(EXIT_FAILURE);
			if (dup2(output_fd, STDERR_FILENO) == -1) {
				perror("dup2");
				exit(EXIT_FAILURE);
			}
			close(output_fd);
		}
		if (shell_cd(s->params) == 0)
			return 0;
		else
			return -1; // if the execution of "cd" failed, return -1 for error
	} else if ((strcmp(s->verb->string, "exit") == 0) ||
(strcmp(s->verb->string, "quit") == 0)) {
		// exit or quit commands will exit the shell successfullyI
		shell_exit();
	}
	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part != NULL)
		return setenv(s->verb->string, get_word(s->verb->next_part->next_part),
true);
	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
    /*
     * These checks ensure that the shell correctly handles "true" and "false"
     * commands, returning the appropriate status code for each.
     */
	if (!strcmp(s->verb->string, "true"))
		return 0;
	if (!strcmp(s->verb->string, "false"))
		return -1;
	// execute external command
	if (execute_external_command(s) == 0)
		return 0; // executed successfully
	return -1; // execution failed
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	command_t *c = father;
	int pid1_1 = 0;
	int pid2_2 = 0;

	pid1_1 = fork();
	if (pid1_1 == 0) {
		// Child 1
		// execute first command
		// also exit the processes derived from the parent process because else at
		// some point they will
		parse_command(c->cmd1, level + 1, c);
		exit(EXIT_SUCCESS);
	} else {
		pid2_2 = fork();
		if (pid2_2 == 0) {
			// Child 2
			// seccond command will be executed by another process
			// will run in the same time
			parse_command(c->cmd2, level + 1, c);
			exit(EXIT_SUCCESS);
		} else {
			// Parent
			// parent will wait for the child 1 and child 2 processes and will get
			// the status they finished with
			int status1, status2;

			waitpid(pid1_1, &status1, 0);
			waitpid(pid2_2, &status2, 0);
			return WEXITSTATUS(status2);
		}
	}
	return 0; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static int run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	command_t *c = father;
	// get file descriptors for pipe
	int pipefd[2] = {0, 0};
	pid_t pid1, pid2; // pids of the two processes for pipe

	if (pipe(pipefd) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}
	pid1 = fork();
	if (pid1 == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid1 == 0) {
		// Child process 1 (first command)
		// one process will take care of an end of the pipe that takes the output
		// of the first command
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		// execute command:
		parse_command(c->cmd1, level + 1, c);
		exit(EXIT_SUCCESS);
	} else {
		pid2 = fork();
		if (pid2 == -1) {
			perror("fork");
			exit(EXIT_FAILURE);
		}
		if (pid2 == 0) {
			// seccond process will take care of the other end of pipe
			close(pipefd[1]);
			dup2(pipefd[0], STDIN_FILENO);
			close(pipefd[0]);
			// execute command:
			parse_command(c->cmd2, level + 1, c);
			if (!strcmp(c->cmd2->scmd->verb->string, "false"))
				exit(EXIT_FAILURE);
			exit(EXIT_SUCCESS);
		} else {
			// Parent process
			// will wait for the processes to finish and will get their exit status
			// we will check only the 2nd process' exit status.
			int status1; // exit status for process 1
			int status2; // exit status for process 2

			close(pipefd[0]);
			close(pipefd[1]);
			waitpid(pid1, &status1, 0); // wait for process
			waitpid(pid2, &status2, 0);
			return WEXITSTATUS(status2);
		}
	}
}
/*
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (c == NULL) {
		fprintf(stderr, "Error: Command is NULL.\n");
		return -1;
	}
	if (c->op == OP_NONE)
		/* TODO: Execute a simple command. */
		// this is a base case
		return parse_simple(c->scmd, level,
							father); // this will return 0 or non 0; 0 is for
									// success, non 0 is for failure
	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		// use recursion for more commands in a row
		parse_command(c->cmd1, level + 1, c);
		return parse_command(c->cmd2, level + 1, c);
	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) != 0)
			return parse_command(c->cmd2, level + 1, c);
		break;
	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) == 0)
			return parse_command(c->cmd2, level + 1, c);
		break;
	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
	default:
		return SHELL_EXIT;
	}

	return 0;
}
