/******************************************************************************/
/* Important Spring 2015 CSCI 402 usage information:                          */
/*                                                                            */
/* This fils is part of CSCI 402 kernel programming assignments at USC.       */
/* Please understand that you are NOT permitted to distribute or publically   */
/*         display a copy of this file (or ANY PART of it) for any reason.    */
/* If anyone (including your prospective employer) asks you to post the code, */
/*         you must inform them that you do NOT have permissions to do so.    */
/* You are also NOT permitted to remove or alter this comment block.          */
/* If this comment block is removed or altered in a submitted file, 20 points */
/*         will be deducted.                                                  */
/******************************************************************************/

#include "kernel.h"
#include "config.h"
#include "globals.h"
#include "errno.h"

#include "util/debug.h"
#include "util/list.h"
#include "util/string.h"
#include "util/printf.h"

#include "proc/kthread.h"
#include "proc/proc.h"
#include "proc/sched.h"
#include "proc/proc.h"

#include "mm/slab.h"
#include "mm/page.h"
#include "mm/mmobj.h"
#include "mm/mm.h"
#include "mm/mman.h"

#include "vm/vmmap.h"

#include "fs/vfs.h"
#include "fs/vfs_syscall.h"
#include "fs/vnode.h"
#include "fs/file.h"

proc_t *curproc = NULL; /* global */
static slab_allocator_t *proc_allocator = NULL;

static list_t _proc_list;
static proc_t *proc_initproc = NULL; /* Pointer to the init process (PID 1) */

void
proc_init()
{
        list_init(&_proc_list);
        proc_allocator = slab_allocator_create("proc", sizeof(proc_t));
        KASSERT(proc_allocator != NULL);
}

proc_t *
proc_lookup(int pid)
{
        proc_t *p;
        list_iterate_begin(&_proc_list, p, proc_t, p_list_link) {
                if (p->p_pid == pid) {
                        return p;
                }
        } list_iterate_end();
        return NULL;
}

list_t *
proc_list()
{
        return &_proc_list;
}

static pid_t next_pid = 0;

/**
 * Returns the next available PID.
 *
 * Note: Where n is the number of running processes, this algorithm is
 * worst case O(n^2). As long as PIDs never wrap around it is O(n).
 *
 * @return the next available PID
 */
static int
_proc_getid()
{
        proc_t *p;
        pid_t pid = next_pid;
        while (1) {
failed:
                list_iterate_begin(&_proc_list, p, proc_t, p_list_link) {
                        if (p->p_pid == pid) {
                                if ((pid = (pid + 1) % PROC_MAX_COUNT) == next_pid) {
                                        return -1;
                                } else {
                                        goto failed;
                                }
                        }
                } list_iterate_end();
                next_pid = (pid + 1) % PROC_MAX_COUNT;
                return pid;
        }
}

/*
 * The new process, although it isn't really running since it has no
 * threads, should be in the PROC_RUNNING state.
 *
 * Don't forget to set proc_initproc when you create the init
 * process. You will need to be able to reference the init process
 * when reparenting processes to the init process.
 */
proc_t *
proc_create(char *name)
{
	/* NOT_YET_IMPLEMENTED("PROCS: proc_create");
	 return NULL;
	 */
	dbg(DBG_PRINT, "INFO : executing proc_create \n");

	int pid = _proc_getid();
	KASSERT(PID_IDLE != pid || list_empty(&_proc_list)); 	/* pid can only be PID_IDLE if this is the first process */
	dbg(DBG_PRINT, "(GRADING1A 2.a)\n");
	KASSERT(PID_INIT != pid || PID_IDLE == curproc->p_pid); /* pid can only be PID_INIT when creating from idle process */
	dbg(DBG_PRINT, "(GRADING1A 2.a)\n");

	/* create new process */
	proc_t* new_proc = slab_obj_alloc(proc_allocator);
	KASSERT(NULL != new_proc);

	/* set process attributes */
	new_proc->p_pid = pid;
	strncpy(new_proc->p_comm, name, PROC_NAME_LEN);
	new_proc->p_comm[PROC_NAME_LEN - 1] = '\0';
	list_init(&(new_proc->p_threads)); 	/* initialize list  to track list of threads */
	list_init(&(new_proc->p_children)); /* initialize list to track list of children */

	if(PID_IDLE == pid) {
		dbg(DBG_PRINT, "(GRADING1A)\n");
		new_proc->p_pproc = NULL; /* parent process is the current process that's running */
	}else {
		dbg(DBG_PRINT, "(GRADING1A)\n");
		new_proc->p_pproc = curproc;
	}
	new_proc->p_status = NULL;
	new_proc->p_state = PROC_RUNNING;
	sched_queue_init(&(new_proc->p_wait)); 		/* initialize wait queue */
	/*new_proc->p_wait = NULL;*/
	new_proc->p_pagedir = pt_create_pagedir(); 	/* create page directory for the process */
	KASSERT(NULL!=new_proc->p_pagedir);
	list_link_init(&(new_proc->p_list_link));
	list_link_init(&(new_proc->p_child_link));
	list_insert_tail(&_proc_list, &(new_proc->p_list_link));
	if (NULL != curproc) {
		dbg(DBG_PRINT, "(GRADING1A)\n");
		list_insert_tail(&(curproc->p_children), &(new_proc->p_child_link)); /* for idle process, there is no curproc */
	}

	/* set initproc global variable */
	if (PID_INIT == new_proc->p_pid) {
		dbg(DBG_PRINT, "(GRADING1A)\n");
		proc_initproc = new_proc;
	}

	/* VFS-related: */
	int index = 0;
	for (index = 0; index < NFILES; index++) {
		new_proc->p_files[index] = NULL;
	}
	new_proc->p_cwd = NULL; 		/* current working directory */

	/* VM */
	new_proc->p_brk = NULL; 		/* process break; see brk(2) */
	new_proc->p_start_brk = NULL; 	/* initial value of process break */
	new_proc->p_vmmap = NULL; 		/* list of areas mapped into */

	dbg(DBG_PRINT, "INFO : new process created with PID = %d \n", new_proc->p_pid);
	return new_proc;
}

/**
 * Cleans up as much as the process as can be done from within the
 * process. This involves:
 *    - Closing all open files (VFS)
 *    - Cleaning up VM mappings (VM)
 *    - Waking up its parent if it is waiting
 *    - Reparenting any children to the init process
 *    - Setting its status and state appropriately
 *
 * The parent will finish destroying the process within do_waitpid (make
 * sure you understand why it cannot be done here). Until the parent
 * finishes destroying it, the process is informally called a 'zombie'
 * process.
 *
 * This is also where any children of the current process should be
 * reparented to the init process (unless, of course, the current
 * process is the init process. However, the init process should not
 * have any children at the time it exits).
 *
 * Note: You do _NOT_ have to special case the idle process. It should
 * never exit this way.
 *
 * @param status the status to exit the process with
 */
void
proc_cleanup(int status)
{
	dbg(DBG_PRINT, "INFO : executing proc_cleanup\n");
	/* This function is called when a thread that exits is the last thread of the process
	 * for(int i =0 ; i<NFILES; i++)
	 * 		close(i)
	 * 	sched_wakeup_on(curproc->p_pproc->p_wait);
	 * 	KASSERT(INIT_PID != curproc->p_pid);
	 * 	loop over all children process to reparent to INIT process
	 * 		curproc->child->(p_pproc->p_id) = INIT_PID
	 * 	curporc->state = PROC_DEAD
	 * 	curproc->status =status
	 * 	set the process to PROC_DEAD (Zombie process)
	 * 	sched_switch();
	 */

	/* NOT_YET_IMPLEMENTED("PROCS: proc_cleanup"); */

	KASSERT(NULL != proc_initproc); /* init process cannot be NULL, we need to reparent child processes */
	dbg(DBG_PRINT, "(GRADING1A 2.b)\n");
	KASSERT(NULL != curproc); 	/* when cleanup is called, curproc cannot be NULL*/
	KASSERT(1 <= curproc->p_pid); /* this process should not be idle process, process cannot be idle process, == KASSERT(PID_IDLE != curproc->p_pid); */
	dbg(DBG_PRINT, "(GRADING1A 2.b)\n");
	KASSERT(NULL != curproc->p_pproc); /* this process should have parent process */
	dbg(DBG_PRINT, "(GRADING1A 2.b)\n");

	dbg(DBG_PRINT, "INFO : reparenting the children's of the current process to INIT, curproc PID = %d, curproc's parent PID = %d\n", curproc->p_pid, curproc->p_pproc->p_pid);
	/* iterate over all the child processes */
	proc_t *p;
	list_iterate_begin(&curproc->p_children, p, proc_t, p_child_link)
	{
		KASSERT(NULL != p);
		dbg(DBG_PRINT, "INFO : reparenting child %d to INIT\n", p->p_pid);
		list_remove(&p->p_child_link); 	/* removes the child from its parent list using next and prev pointers */
		list_insert_tail(&(proc_initproc->p_children), &(p->p_child_link));
		p->p_pproc = proc_initproc;
	}list_iterate_end();

	curproc->p_status = status; 		/* set the status for the current process, this will be returned to the parent when it calls do_waitpid() */
	curproc->p_state = PROC_DEAD; 		/* mark the process is DEAD */
	KASSERT(NULL != &(curproc->p_pproc->p_wait));
	dbg(DBG_PRINT, "INFO : waking up the parent of the current process in case if it is waiting\n");
	sched_wakeup_on(&(curproc->p_pproc->p_wait)); /* wake up the parent process it may wait for the child to die */

	KASSERT(NULL != curproc->p_pproc); /* this process should have parent process */
	dbg(DBG_PRINT, "(GRADING1A 2.b)\n");
	dbg(DBG_PRINT, "INFO : finished cleaning up process %d\n", curproc->p_pid);
}

/*
 * This has nothing to do with signals and kill(1).
 *
 * Calling this on the current process is equivalent to calling
 * do_exit().
 *
 * In Weenix, this is only called from proc_kill_all.
 */
void
proc_kill(proc_t *p, int status)
{
	/*
	 * Cancel all threads, join with them, and exit from the current thread.
	 * for(int i =0 ; i<NFILES; i++)
	 * 		close(i);
	 * for all threads (p->pthreads)
	 * 		kthread_cancel(thr, 0); // gets to cancel kthread_exit after getting CPU
	 * 		sched_make_runnable(kt_runqueue, thr);
	 * p->state = PROC_DEAD
	 * p->status = status
	 * sched_wakeup_on(p->parent->p_wait); // parent could be waiting for it to die
	 * sched_switch(); // if its the curproc then it has to find a alternative process for CPU
	 * Doubts : What will happen to the child processes coz the description doesn't specify anything about?
	 * reparent the child processes to INIT process
	 *
	 */

	/* NOT_YET_IMPLEMENTED("PROCS: proc_kill"); */

	dbg(DBG_PRINT, "INFO : executing proc_kill\n");
	KASSERT(NULL != p); 	/* process should not be NULL */
	KASSERT(PID_IDLE != p->p_pid && PID_IDLE != p->p_pproc->p_pid);

	if(curproc == p) {
		dbg(DBG_PRINT, "(GRADING1C 9)\n");
		dbg(DBG_PRINT, "INFO : proc_kill is called on the curproc\n");
		kthread_cancel(curthr, (void*)status);
		return;
	}

	dbg(DBG_PRINT, "INFO : reparenting the children's of the given process to INIT, process PID = %d, process's parent PID = %d\n", p->p_pid, p->p_pproc->p_pid);
	/* iterate over all the child processes and re-parent them */
	proc_t* child;
	list_iterate_begin(&p->p_children, child, proc_t, p_child_link)
	{
		KASSERT(NULL != child);
		dbg(DBG_PRINT, "INFO : reparenting child %d to INIT\n", child->p_pid);
		list_remove(&child->p_child_link); /* removes the child from its list using its next and prev pointers */
		list_insert_tail(&(proc_initproc->p_children), &(child->p_child_link));
		child->p_pproc = proc_initproc;
	}list_iterate_end();

	dbg(DBG_PRINT, "INFO : place cancel request on the process's threads in case required\n");
	/* iterate over threads and cancel them */
	kthread_t *thr;
	list_iterate_begin(&p->p_threads, thr, kthread_t, kt_plink)
	{
		KASSERT(NULL != thr);
		if(KT_EXITED != thr->kt_state || KT_NO_STATE != thr->kt_state){ /* thread is in waitQ or runQ */
			dbg(DBG_PRINT, "(GRADING1C 8)\n");
			dbg(DBG_PRINT, "INFO : placing the cancel request on process's thread\n");
			kthread_cancel(thr, (void*)-1); /* cancel the thread */
		}
		/* this thread need not be removed from the thread list now. it can be handled in the do_waitpid */
	}list_iterate_end();
/* don't know if this path should be tested*/
}

/*
 * Remember, proc_kill on the current process will _NOT_ return.
 * Don't kill direct children of the idle process.
 *
 * In Weenix, this is only called by sys_halt.
 */
void
proc_kill_all()
{
	/* NOT_YET_IMPLEMENTED("PROCS: proc_kill_all");*/
	dbg(DBG_PRINT, "INFO : executing proc_kill_all\n");
	proc_t* child;
	list_iterate_begin(&_proc_list, child, proc_t, p_list_link)
	{
		KASSERT(NULL != child);
		/* kill all the process except IDLE and direct children of IDLE */
		if (PROC_DEAD != child->p_state && curproc != child && PID_IDLE != child->p_pid && PID_IDLE != child->p_pproc->p_pid) {
			dbg(DBG_PRINT, "(GRADING1C 9)\n");
			dbg(DBG_PRINT, "INFO : kill process %d\n", child->p_pid);
			proc_kill(child, child->p_status);
		}
	}list_iterate_end();

	if(PID_IDLE != curproc->p_pproc->p_pid) {
		dbg(DBG_PRINT, "(GRADING1C 9)\n");
		dbg(DBG_PRINT, "INFO : kill the current process %d\n", curproc->p_pid);
		proc_kill(curproc, curproc->p_status);
	}
}

/*
 * This function is only called from kthread_exit.
 *
 * Unless you are implementing MTP, this just means that the process
 * needs to be cleaned up and a new thread needs to be scheduled to
 * run. If you are implementing MTP, a single thread exiting does not
 * necessarily mean that the process should be exited.
 */
void
proc_thread_exited(void *retval)
{
	/* This will be executed only by the current executing thread
	 * remove the current thread from current process
	 * if(isEmpty(curthr->p_threads)) {
	 * 		proc_cleanup(curproc->status)
	 * 	}
	 * 	sched_switch();
	 */

	/* NOT_YET_IMPLEMENTED("PROCS: proc_thread_exited");*/
	dbg(DBG_PRINT, "(GRADING1C 1)\n");
	dbg(DBG_PRINT, "INFO : executing proc_thread_exited\n");
	KASSERT(NULL != curproc);
	/*if (list_empty(&(curproc->p_threads)))*/
	proc_cleanup((int)retval);
	sched_switch();
}

void proc_cleanup_memory(proc_t* dead_proc) {
	dbg(DBG_PRINT, "INFO : executing proc_cleanup_memory\n");
	/* cleanup the thread space of the dead process */
	kthread_t* thr;
	list_iterate_begin(&(dead_proc->p_threads), thr, kthread_t, kt_plink) {
		KASSERT(KT_EXITED == thr->kt_state);
		dbg(DBG_PRINT, "(GRADING1A 2.c)\n");
		kthread_destroy(thr);
	}list_iterate_end();

	/* clean up process space */
	dbg(DBG_PRINT, "INFO : removing process links\n");
	if (list_link_is_linked(&dead_proc->p_list_link)){
		dbg(DBG_PRINT, "(GRADING1A)\n");
		list_remove(&dead_proc->p_list_link); 	/* remove child from the global list */
	}
	if (list_link_is_linked(&dead_proc->p_child_link)) {
		dbg(DBG_PRINT, "(GRADING1A)\n");
		list_remove(&dead_proc->p_child_link); /* remove child from parents(curproc) child list */
	}
	KASSERT(NULL != dead_proc->p_pagedir);  /* this process should have a valid pagedir */
	dbg(DBG_PRINT, "(GRADING1A 2.c)\n");
	dbg(DBG_PRINT, "INFO : removing page directory\n");
	pt_destroy_pagedir(dead_proc->p_pagedir); /* destroy the page directory of the process */
	KASSERT(NULL != proc_allocator); /* there should be a valid proc allocator */
	dbg(DBG_PRINT, "INFO : removing proc_allocator\n");
	slab_obj_free(proc_allocator, dead_proc); /* free up the space allocated for this dead process */
}

/* If pid is -1 dispose of one of the exited children of the current
 * process and return its exit status in the status argument, or if
 * all children of this process are still running, then this function
 * blocks on its own p_wait queue until one exits.
 *
 * If pid is greater than 0 and the given pid is a child of the
 * current process then wait for the given pid to exit and dispose
 * of it.
 *
 * If the current process has no children, or the given pid is not
 * a child of the current process return -ECHILD.
 *
 * Pids other than -1 and positive numbers are not supported.
 * Options other than 0 are not supported.
 */
pid_t
do_waitpid(pid_t pid, int options, int *status)
{
	/* NOT_YET_IMPLEMENTED("PROCS: do_waitpid");
	 return 0;
	 */
	dbg(DBG_PRINT, "INFO : executing do_waitpid\n");
	dbg(DBG_PRINT, "INFO : %d waiting for %d to die\n", curproc->p_pid, pid);
	KASSERT(NULL != curproc && NULL!= &(curproc->p_children));
	KASSERT((NULL != pid && pid>0) || (-1 == pid));
	KASSERT(0 == options);
	if (list_empty(&curproc->p_children)) {
		dbg(DBG_PRINT, "(GRADING1A)\n");
		dbg(DBG_PRINT, "INFO : no children found, so returns -ECHILD \n");
		if(status) {
			dbg(DBG_PRINT, "(GRADING1C 1)\n");
			*status = -1;
		}
		return -ECHILD;
	}

	int pid_found = 0;
	int found_dead_child = 0; /* to capture dead child PID */
	proc_t* dead_child;

	proc_t* child;
	wait_pid: /* label for goto */
	list_iterate_begin(&curproc->p_children, child, proc_t, p_child_link)
	{
		if (-1 == pid) { /* user is not interested in specific pid */
			dbg(DBG_PRINT, "(GRADING1A)\n");
			pid_found = 1;
			if (PROC_DEAD == child->p_state) { /* any of the child process is dead */
				dbg(DBG_PRINT, "(GRADING1A)\n");
				found_dead_child = 1;
				dead_child = child;
				break; /* once we found the child that's dead */
			}
		} else {
			dbg(DBG_PRINT, "(GRADING1C 1)\n");
			if (pid == child->p_pid) {
				dbg(DBG_PRINT, "(GRADING1C 1)\n");
				pid_found = 1;
				pid_check: /* label for goto */
				if (PROC_DEAD == child->p_state) {
					dbg(DBG_PRINT, "(GRADING1C 1)\n");
					found_dead_child = 1;
					dead_child = child;
					break; /* process is dead (given pid) */
				} else {
					dbg(DBG_PRINT, "(GRADING1C 1)\n");
					dbg(DBG_PRINT, "INFO : process %d is not dead yet. so, the curproc(PID = %d) goes for sleep \n", pid, curproc->p_pid);
					sched_sleep_on(&curproc->p_wait);
					dbg(DBG_PRINT, "INFO : process %d woke up \n", curproc->p_pid);
					goto pid_check; /* if some other thread/process wakes up this process */
				}
			}
		}
	}list_iterate_end();

	if (0 == pid_found) {
		dbg(DBG_PRINT, "(GRADING1C 1)\n");
		dbg(DBG_PRINT, "INFO : given pid(%d) is not found in the curproc's child list\n", pid);
		if(status) {
			dbg(DBG_PRINT, "(GRADING1C 1)\n");
			*status = -1;
		}
		return -ECHILD; /*given PID couldnt be found from the curpocess child list */
	}
	if (0 == found_dead_child) {
		dbg(DBG_PRINT, "(GRADING1A)\n"); /* Process is fond and it is not dead, wait for it till it dies */
		dbg(DBG_PRINT, "INFO : none of the child processes of the given process(PID = %d) is not dead yet. so, it goes for sleep\n", curproc->p_pid);
		sched_sleep_on(&curproc->p_wait);
		dbg(DBG_PRINT, "INFO : process %d woke up \n", curproc->p_pid);
		goto wait_pid;
	} else {
		dbg(DBG_PRINT, "(GRADING1A)\n"); /* found_dead_child ==  1*/
		KASSERT(NULL != dead_child);  /* the dead child process should not be NULL */
		dbg(DBG_PRINT, "(GRADING1A 2.c)\n");
		pid_t dead_child_pid = dead_child->p_pid;
		KASSERT(-1 == dead_child_pid || dead_child->p_pid == dead_child_pid); /* should be able to find a valid process ID for the process */
		dbg(DBG_PRINT, "INFO : found dead child %d, parent pid = %d\n", dead_child_pid,curproc->p_pid);
		dbg(DBG_PRINT, "(GRADING1A 2.c)\n");
		if(status) {
			dbg(DBG_PRINT, "(GRADING1A)\n");
			*status = dead_child->p_status;
		}

		proc_cleanup_memory(dead_child);
		return dead_child_pid;
	}
}

/*
 * Cancel all threads, join with them, and exit from the current
 * thread.
 *
 * @param status the exit status of the process
 */
void
do_exit(int status)
{
	dbg(DBG_PRINT, "INFO : executing do_exit\n");
	/* NOT_YET_IMPLEMENTED("PROCS: do_exit"); */
	kthread_exit((void *) status);
}

size_t
proc_info(const void *arg, char *buf, size_t osize)
{
        const proc_t *p = (proc_t *) arg;
        size_t size = osize;
        proc_t *child;

        KASSERT(NULL != p);
        KASSERT(NULL != buf);

        iprintf(&buf, &size, "pid:          %i\n", p->p_pid);
        iprintf(&buf, &size, "name:         %s\n", p->p_comm);
        if (NULL != p->p_pproc) {
                iprintf(&buf, &size, "parent:       %i (%s)\n",
                        p->p_pproc->p_pid, p->p_pproc->p_comm);
        } else {
                iprintf(&buf, &size, "parent:       -\n");
        }

#ifdef __MTP__
        int count = 0;
        kthread_t *kthr;
        list_iterate_begin(&p->p_threads, kthr, kthread_t, kt_plink) {
                ++count;
        } list_iterate_end();
        iprintf(&buf, &size, "thread count: %i\n", count);
#endif

        if (list_empty(&p->p_children)) {
                iprintf(&buf, &size, "children:     -\n");
        } else {
                iprintf(&buf, &size, "children:\n");
        }
        list_iterate_begin(&p->p_children, child, proc_t, p_child_link) {
                iprintf(&buf, &size, "     %i (%s)\n", child->p_pid, child->p_comm);
        } list_iterate_end();

        iprintf(&buf, &size, "status:       %i\n", p->p_status);
        iprintf(&buf, &size, "state:        %i\n", p->p_state);

#ifdef __VFS__
#ifdef __GETCWD__
        if (NULL != p->p_cwd) {
                char cwd[256];
                lookup_dirpath(p->p_cwd, cwd, sizeof(cwd));
                iprintf(&buf, &size, "cwd:          %-s\n", cwd);
        } else {
                iprintf(&buf, &size, "cwd:          -\n");
        }
#endif /* __GETCWD__ */
#endif

#ifdef __VM__
        iprintf(&buf, &size, "start brk:    0x%p\n", p->p_start_brk);
        iprintf(&buf, &size, "brk:          0x%p\n", p->p_brk);
#endif

        return size;
}

size_t
proc_list_info(const void *arg, char *buf, size_t osize)
{
        size_t size = osize;
        proc_t *p;

        KASSERT(NULL == arg);
        KASSERT(NULL != buf);

#if defined(__VFS__) && defined(__GETCWD__)
        iprintf(&buf, &size, "%5s %-13s %-18s %-s\n", "PID", "NAME", "PARENT", "CWD");
#else
        iprintf(&buf, &size, "%5s %-13s %-s\n", "PID", "NAME", "PARENT");
#endif

        list_iterate_begin(&_proc_list, p, proc_t, p_list_link) {
                char parent[64];
                if (NULL != p->p_pproc) {
                        snprintf(parent, sizeof(parent),
                                 "%3i (%s)", p->p_pproc->p_pid, p->p_pproc->p_comm);
                } else {
                        snprintf(parent, sizeof(parent), "  -");
                }

#if defined(__VFS__) && defined(__GETCWD__)
                if (NULL != p->p_cwd) {
                        char cwd[256];
                        lookup_dirpath(p->p_cwd, cwd, sizeof(cwd));
                        iprintf(&buf, &size, " %3i  %-13s %-18s %-s\n",
                                p->p_pid, p->p_comm, parent, cwd);
                } else {
                        iprintf(&buf, &size, " %3i  %-13s %-18s -\n",
                                p->p_pid, p->p_comm, parent);
                }
#else
                iprintf(&buf, &size, " %3i  %-13s %-s\n",
                        p->p_pid, p->p_comm, parent);
#endif
        } list_iterate_end();
        return size;
}
