# Pintos User Programs

Welcome to the Pintos Operating System repository! This is a implementations of running user programs in pintos operating system developed as part of an assignment for the operating system module.

## Project Overview

The main objectives of this project include:

1. **Process Termination Messages**: Whenever a user process terminates, either by calling `exit` or for any other reason, we print the process's name and exit code in the format of `"%s: exit(%d)\n"`. The name printed is the full name passed to `process_execute()`, excluding command-line arguments.

2. **Argument Passing**: We extend `process_execute()` to support passing arguments to new processes. The program name and its arguments are divided by spaces, allowing us to execute commands like `"grep foo bar"` with `grep` as the program name and `foo` and `bar` as arguments.

3. **Accessing User Memory**: The kernel must carefully handle memory access through pointers provided by user programs, ensuring that null pointers, pointers to unmapped virtual memory, and pointers to kernel virtual address space are rejected without harming the kernel or other processes.

4. **System Calls**: We implement a system call handler in `userprog/syscall.c`. This handler retrieves the system call number, its arguments, and carries out the appropriate actions. We implement several system calls including `halt`, `exit`, `exec`, `wait`, `create`, `remove`, `open`, `filesize`, `read`, `write`, `seek`, `tell`, and `close`. Each of these system calls has specific functionality and behavior detailed in the project description.

## Project Exercises

Here's a summary of the project exercises:

### Exercise 1.1: Process Termination Messages
Implement process termination messages in the format `"%s: exit(%d)\n"` when a process terminates.

### Exercise 2.1: Argument Passing
Extend `process_execute()` to support passing arguments to new processes.

### Exercise 3.1: Accessing User Memory
Implement reading from and writing to user memory for system calls. Ensure proper handling of invalid user pointers.

### Exercise 4.1: System Call Handler
Implement the system call handler in `userprog/syscall.c`. Retrieve the system call number, arguments, and perform the required actions.

### Exercise 4.2: Implement System Calls
Implement the following system calls with their specified functionality: `halt`, `exit`, `exec`, `wait`, `create`, `remove`, `open`, `filesize`, `read`, `write`, `seek`, `tell`, and `close`.

## Getting Started

To build and run the Pintos operating system with your implemented features, follow these steps:

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/pintos.git
   cd pintos
   ```

2. Build Pintos:
   ```bash
   make
   ```

3. Run tests:
   ```bash
   make check
   ```

## Additional Notes

- Be sure to thoroughly test your code to handle all corner cases.
- Remember that Pintos should not crash or malfunction due to user program actions; only the `halt` system call should terminate Pintos.
- You may refer to the provided code and hints in the project description for guidance.

Please feel free to reach out if you have any questions or need assistance with this project. Good luck with your implementation!
