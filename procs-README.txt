Documentation for Kernel Assignment 1
=====================================

+-------------+
| BUILD & RUN |
+-------------+

Comments: No comments

+-----------------+
| SKIP (Optional) |
+-----------------+

Every test in the standard test-suite runs properly.

+---------+
| GRADING |
+---------+

(A.1) In main/kmain.c:
    (a) In bootstrap(): 3 out of 3 pts
    (b) In initproc_create():  3 out of 3 pts

(A.2) In proc/proc.c:
    (a) In proc_create():  4 out of 4 pts
    (b) In proc_cleanup():  5 out of 5 pts
    (c) In do_waitpid():  8 out of 8 pts

(A.3) In proc/kthread.c:
    (a) In kthread_create(): 2 out of 2 pts
    (b) In kthread_cancel(): 1 out of 1 pt
    (c) In kthread_exit():  3 out of 3 pts

(A.4) In proc/sched.c:
    (a) In sched_wakeup_on(): 1 out of 1 pt
    (b) In sched_make_runnable(): 1 out of 1 pt

(A.5) In proc/kmutex.c:
    (a) In kmutex_lock(): 1 out of 1 pt
    (b) In kmutex_lock_cancellable(): 1 out of 1 pt
    (c) In kmutex_unlock(): 2 out of 2 pts

(B) Kshell : 20 out of 20 pts
    Comments: None

(C.1) waitpid any test, etc. (4 out of 4 pts)
(C.2) Context switch test (1 out of 1 pt)
(C.3) wake me test, etc. (2 out of 2 pts)
(C.4) wake me uncancellable test, etc. (2 out of 2 pts)
(C.5) cancel me test, etc. (4 out of 4 pts)
(C.6) reparenting test, etc. (2 out of 2 pts)
(C.7) show race test, etc. (3 out of 3 pts)
(C.8) kill child procs test (2 out of 2 pts)
(C.9) proc kill all test (2 out of 2 pts)

(D.1) sunghan_test(): producer/consumer test (9 out of 9 pts)
(D.2) sunghan_deadlock_test(): deadlock test (4 out of 4 pts)

(E) Additional self-checks: (10 out of 10 pts)
    Comments: By running all the tests in the above sections, all code paths are exercised

Missing required section(s) in README file (procs-README.txt): Not missing any sections
Submitted binary file : No binary files submitted
Submitted extra (unmodified) file : None
Wrong file location in submission : None
Use dbg_print(...) instead of dbg(DBG_PRINT, ...) : Nowhere
Not properly indentify which dbg() printout is for which item in the grading guidelines : Every dbg() printout properly identifies the item in grading guidelines
Cannot compile : Kernel is properly compliling
Compiler warnings : None
"make clean" : Works
Useless KASSERT : No
Insufficient/Confusing dbg : None
Kernel panic : No
Cannot halt kernel cleanly : Kernel halts cleanly

+------+
| BUGS |
+------+

None

+---------------------------+
| CONTRIBUTION FROM MEMBERS |
+---------------------------+

Equal Contribution from all members (hansalsh@usc.edu, yshankar@usc.edu, kmanek@usc.edu, mukhin@usc.edu)

+------------------+
| OTHER (Optional) |
+------------------+

Special DBG setting in Config.mk for certain tests: No
Comments on deviation from spec (you will still lose points, but it's better to let the grader know): There is no deviation from spec
General comments on design decisions: No


