angr strategies cheat sheet
===========================

This cheat sheet summarises "strategies" (or techniques) to use with angr, seen in various examples of the
[angr-doc repository](https://github.com/angr/angr-doc).

Hooks
-----
If the program is statically linked:

- (manually) identify libc calls (or calls to functions similar to libc ones; may take a long time to find them)
- add hooks on these calls

If the program calls ptrace():

- add a `ReturnUnconstrained` simulation procedure

Init state
----------
- use angr.options.unicorn
- if a program uses syscalls that should not be handled, use `BYPASS_UNSUPPORTED_SYSCALL`
- if some memory or registers bytes are known, concatenate a `BVV` and a `BVS` (e.g.
  `claripy.BVV(0, 56).concat(claripy.BVS('rdi', 8))`)

Input
-----
If the program takes input from `argv`:

- (manually) find the expected length of `argv`
- add a non-null constraint on characters

If the program takes printable input:

- add a printable constraint on characters

If the program reads input from a file:

- (manually) find the expected length of the file
- use the filesystem feature of angr

Execution with a known goal path or output
------------------------------------------
- use `simgr.explore()`
- if using `simgr.explore()` several times, use `simgr.unstash()` to move states from the `found` stash to the `active`
  stash
- search flags in the outputs of the states of the `found` stash

"Blind" execution
-----------------
- periodically trim the `deadended` and `errored` stashes (also useful for memory optimization) ...
- ... and when the `active` stash is empty, search for the flag in the outputs of the states in the `deadended` stash
  (this means searching for the flag in the outputs of the states that have survived the longest time)

See [Fish Wang's solution of TUMCTF 2016 - zwiebel](
https://github.com/angr/angr-doc/tree/master/examples/tumctf2016_zwiebel/solve.py).

Execution when searching for memory corruption
----------------------------------------------
- use `project.factory.simgr(save_unconstrained=True)` and symbolically execute the binary until an unconstrained path
  is reached
- use a simulation technique to find paths that lead to a `NULL` program counter

See [Audrey Dutcher's demonstration of the GRUB "back to 28" bug](
https://github.com/angr/angr-doc/tree/master/examples/grub/solve.py).

Execution when searching for a shellcode injection vulnerability
----------------------------------------------------------------
- find a fully symbolic program counter in the `unconstrained` stash
- search for a buffer controlled by user input, ie. a buffer which holds symbols whose names contain `file` or
  `stdin.ident` (use `state.solver.get_variables()` and `state.memory.addrs_for_name()`)
- add as constraints that the buffer's content must be equal to the shellcode, and the program counter equal to the
  address of this buffer

See [Nick Stephens' solution of Insomnihack Simple AEG](
https://github.com/angr/angr-doc/tree/master/examples/insomnihack_aeg/solve.py).

Optimization
------------
If the program takes too much memory too quickly (e.g. 1 GB/s):

- add a simulation technique that checks for state uniqueness

See [Audrey Dutcher's demonstration of the GRUB "back to 28" bug](
https://github.com/angr/angr-doc/tree/master/examples/grub/solve.py).

If the program takes too much memory over several (or tens) of minutes:

- periodically trim the `deadended` and `errored` stashes (also useful for "blind" execution)

If a function leads to path explosion:

- hook it with a custom SimProcedure

Use of results
--------------
If `state.solver.eval(expr)` or `state.solver.eval_upto(expr)` freezes:

- use `state.solver.eval()` or `state.solver.eval_upto()` several times with broken down expressions

See [Yan Shoshitaishvili's solution of Whitehat CTF 2015 - Crypto 400](
https://github.com/angr/angr-doc/tree/master/examples/whitehat_crypto400/solve.py).
