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

#include "globals.h"
#include "errno.h"

#include "util/debug.h"

#include "proc/kthread.h"
#include "proc/kmutex.h"
#include "proc/sched.h"

/*
 * IMPORTANT: Mutexes can _NEVER_ be locked or unlocked from an
 * interrupt context. Mutexes are _ONLY_ lock or unlocked from a
 * thread context.
 */
/*these functions are static and were not defined in sched.h file, so we have to copy-paste them*/
static void
ktqueue_enqueue(ktqueue_t *q, kthread_t *thr)
{
        KASSERT(!thr->kt_wchan);
        list_insert_head(&q->tq_list, &thr->kt_qlink);
        thr->kt_wchan = q;
        q->tq_size++;
}
/*these functions are static and were not defined in sched.h file, so we have to copy-paste them*/
static kthread_t *
ktqueue_dequeue(ktqueue_t *q)
{
        kthread_t *thr;
        list_link_t *link;

        if (list_empty(&q->tq_list))
                return NULL;

        link = q->tq_list.l_prev;
        thr = list_item(link, kthread_t, kt_qlink);
        list_remove(link);
        thr->kt_wchan = NULL;

        q->tq_size--;

        return thr;
}

void
kmutex_init(kmutex_t *mtx)
{
     /*  NOT_YET_IMPLEMENTED("PROCS: kmutex_init"); */
	dbg(DBG_PRINT, "(GRADING1C 7)\n");
	sched_queue_init(&(mtx->km_waitq)); /* init the wait queue in mutex mtx */
	mtx->km_holder = NULL; /* set the mutex holder to null */
}

/*
 * This should block the current thread (by sleeping on the mutex's
 * wait queue) if the mutex is already taken.
 *
 * No thread should ever try to lock a mutex it already has locked.
 */
void
kmutex_lock(kmutex_t *mtx) {
     /* NOT_YET_IMPLEMENTED("PROCS: kmutex_lock"); */
	KASSERT(curthr && (curthr != mtx->km_holder)); /*curthr is not already mutex holder*/
	dbg(DBG_PRINT, "(GRADING1A 5.a)\n");
	if(mtx->km_holder) {
		dbg(DBG_PRINT, "(GRADING1C 7)\n");
		ktqueue_enqueue(&(mtx->km_waitq), curthr);
		sched_switch();
	}
	else {
		dbg(DBG_PRINT, "(GRADING1A)\n");
		mtx->km_holder = curthr;
	};
}

/*
 * This should do the same as kmutex_lock, but use a cancellable sleep
 * instead.
 */
int
kmutex_lock_cancellable(kmutex_t *mtx)
{
       /* NOT_YET_IMPLEMENTED("PROCS: kmutex_lock_cancellable"); */
	KASSERT(curthr && (curthr != mtx->km_holder)); /*making sure curthr is not current mutex holder*/
	dbg(DBG_PRINT, "(GRADING1A 5.b)\n");
	int status =0;
	if(mtx->km_holder) {
		dbg(DBG_PRINT, "(GRADING1C 7)\n");
		/*ktqueue_enqueue(&(mtx->km_waitq), curthr);*/
		status = sched_cancellable_sleep_on(&(mtx->km_waitq));
		/*sched_switch();*/ /* not needed as sched_cancellable_sleep_on is calling sched_swtich*/
	}
	else {
		dbg(DBG_PRINT, "(GRADING1C 7)\n");
		mtx->km_holder = curthr;
	};
        return status;
}

/*
 * If there are any threads waiting to take a lock on the mutex, one
 * should be woken up and given the lock.
 *
 * Note: This should _NOT_ be a blocking operation!
 *
 * Note: Don't forget to add the new owner of the mutex back to the
 * run queue.
 *
 * Note: Make sure that the thread on the head of the mutex's wait
 * queue becomes the new owner of the mutex.
 *
 * @param mtx the mutex to unlock
 */
void
kmutex_unlock(kmutex_t *mtx)
{
       /* NOT_YET_IMPLEMENTED("PROCS: kmutex_unlock"); */
	 KASSERT(curthr && (curthr == mtx->km_holder)); /*make sure curthr is a mutex holder*/
	 dbg(DBG_PRINT, "(GRADING1A 5.c)\n");
	if	(sched_queue_empty(&(mtx->km_waitq))){
		dbg(DBG_PRINT, "(GRADING1A)\n");
		mtx->km_holder = NULL; }
	else
	{
		dbg(DBG_PRINT, "(GRADING1C 7)\n");
		/*dequeue a thread from mutex wait queue*/
		kthread_t *new_thr = ktqueue_dequeue(&(mtx->km_waitq));
		mtx->km_holder = new_thr; /*update a pointer to current mutex holder*/
		sched_make_runnable(new_thr);
	};
	KASSERT(curthr != mtx->km_holder);
	dbg(DBG_PRINT, "(GRADING1A 5.c)\n");
}
