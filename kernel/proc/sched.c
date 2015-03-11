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

#include "main/interrupt.h"

#include "proc/sched.h"
#include "proc/kthread.h"

#include "util/init.h"
#include "util/debug.h"

static ktqueue_t kt_runq;

static __attribute__((unused)) void
sched_init(void)
{
        sched_queue_init(&kt_runq);
}
init_func(sched_init);



/*** PRIVATE KTQUEUE MANIPULATION FUNCTIONS ***/
/**
 * Enqueues a thread onto a queue.
 *
 * @param q the queue to enqueue the thread onto
 * @param thr the thread to enqueue onto the queue
 */
static void
ktqueue_enqueue(ktqueue_t *q, kthread_t *thr)
{
        KASSERT(!thr->kt_wchan);
        list_insert_head(&q->tq_list, &thr->kt_qlink);
        thr->kt_wchan = q;
        q->tq_size++;
}

/**
 * Dequeues a thread from the queue.
 *
 * @param q the queue to dequeue a thread from
 * @return the thread dequeued from the queue
 */
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

/**
 * Removes a given thread from a queue.
 *
 * @param q the queue to remove the thread from
 * @param thr the thread to remove from the queue
 */
static void
ktqueue_remove(ktqueue_t *q, kthread_t *thr)
{
        KASSERT(thr->kt_qlink.l_next && thr->kt_qlink.l_prev);
        list_remove(&thr->kt_qlink);
        thr->kt_wchan = NULL;
        q->tq_size--;
}

/*** PUBLIC KTQUEUE MANIPULATION FUNCTIONS ***/
void
sched_queue_init(ktqueue_t *q)
{
        list_init(&q->tq_list);
        q->tq_size = 0;
}

int
sched_queue_empty(ktqueue_t *q)
{
        return list_empty(&q->tq_list);
}

/*
 * Updates the thread's state and enqueues it on the given
 * queue. Returns when the thread has been woken up with wakeup_on or
 * broadcast_on.
 *
 * Use the private queue manipulation functions above.
 */
void
sched_sleep_on(ktqueue_t *q)
{
	dbg(DBG_PRINT, "INFO : executing sched_sleep_on\n");
	dbg(DBG_PRINT, "(GRADING1A)\n");
     /*NOT_YET_IMPLEMENTED("PROCS: sched_sleep_on");*/
	curthr->kt_state = KT_SLEEP;
	ktqueue_enqueue(q, curthr);
	sched_switch();
}


/*
 * Similar to sleep on, but the sleep can be cancelled.
 *
 * Don't forget to check the kt_cancelled flag at the correct times.
 *
 * Use the private queue manipulation functions above.
 */
int
sched_cancellable_sleep_on(ktqueue_t *q)
{
	dbg(DBG_PRINT, "INFO : executing sched_cancellable_sleep_on\n");
    /*NOT_YET_IMPLEMENTED("PROCS: sched_cancellable_sleep_on"); */
	int is_canc = curthr->kt_cancelled;
	if(is_canc) {
		dbg(DBG_PRINT, "(GRADING1C 5)\n");
		return -EINTR;
	};
	/* set the state of the thread*/
	curthr->kt_state = KT_SLEEP_CANCELLABLE;
	/* enqueue it to the given queue */
	ktqueue_enqueue(q, curthr);
	sched_switch();
	if(curthr->kt_cancelled) {
		dbg(DBG_PRINT, "(GRADING1C 5)\n");
		return -EINTR;
	}
	else {
		dbg(DBG_PRINT, "(GRADING1B)\n"); /*after creating kshell, it waits for the interrupt and goes to cancellable sleep on */
		return 0;
	}
}

kthread_t *
sched_wakeup_on(ktqueue_t *q)
{
	dbg(DBG_PRINT, "INFO : executing sched_wakeup_on\n");
    /* NOT_YET_IMPLEMENTED("PROCS: sched_wakeup_on");*/
	KASSERT(q);
	kthread_t* newthr;
	if(sched_queue_empty(q)) {
		dbg(DBG_PRINT, "(GRADING1C 1)\n");
        return NULL;
	};
	/*else dequeue a thread from waiting queue*/
	newthr = ktqueue_dequeue(q);
	/*newthr->kt_state = KT_RUN;*/
	/* remove thread from wait queue*/
	/*ktqueue_remove(q, newthr); */
	/*make that thread runnable, i.e. add it to the run queue*/
	/*if(KT_SLEEP == newthr->kt_state || KT_SLEEP_CANCELLABLE == newthr->kt_state)*/
	KASSERT((newthr->kt_state == KT_SLEEP) || (newthr->kt_state == KT_SLEEP_CANCELLABLE));
	dbg(DBG_PRINT, "(GRADING1A 4.a)\n");
	dbg(DBG_PRINT, "INFO : woken up thread (process ID = %d)\n", newthr->kt_proc->p_pid);
	sched_make_runnable(newthr);
	return newthr;
}

void
sched_broadcast_on(ktqueue_t *q)
{
       /* NOT_YET_IMPLEMENTED("PROCS: sched_broadcast_on"); */
	dbg(DBG_PRINT, "INFO : executing sched_broadcast_on\n");
	KASSERT(q);
	kthread_t* newthr;
	if(sched_queue_empty(q)) {
		dbg(DBG_PRINT, "(GRADING1A)\n"); /*first called by pageoutd*/
	    return;
	};
	while(!sched_queue_empty(q)) { dbg(DBG_PRINT, "(GRADING1C 3)\n");
		newthr = ktqueue_dequeue(q);
		newthr->kt_state = KT_RUN;
		/* remove thread from wait queue*/
		/*ktqueue_remove(q, newthr); */
		/* add that thread to run queue*/
		dbg(DBG_PRINT, "INFO : woken up thread (process ID = %d)\n", newthr->kt_proc->p_pid);
		sched_make_runnable(newthr);
	};
	return;
}

/*
 * If the thread's sleep is cancellable, we set the kt_cancelled
 * flag and remove it from the queue. Otherwise, we just set the
 * kt_cancelled flag and leave the thread on the queue.
 *
 * Remember, unless the thread is in the KT_NO_STATE or KT_EXITED
 * state, it should be on some queue. Otherwise, it will never be run
 * again.
 */
void
sched_cancel(struct kthread *kthr)
{
	dbg(DBG_PRINT, "INFO : executing sched_cancel\n");
     /* NOT_YET_IMPLEMENTED("PROCS: sched_cancel"); */
	dbg(DBG_PRINT, "INFO : sched_cancel on thread(PID = %d)\n", kthr->kt_proc->p_pid);
	KASSERT(!(kthr->kt_state==KT_NO_STATE) && !(kthr->kt_state==KT_EXITED));
	/*get the queue that thread is sleeping on:*/
	ktqueue_t *wait_q = kthr->kt_wchan;

	if(kthr->kt_state == KT_SLEEP_CANCELLABLE) {
		dbg(DBG_PRINT, "(GRADING1C 5)\n");
		dbg(DBG_PRINT, "INFO : thread is in sleep cancellable state. so, it can be canceled and made runnable right away\n");
		kthr->kt_cancelled = 1;
		ktqueue_remove(wait_q, kthr);
		/* add that thread to the run queue*/
		sched_make_runnable(kthr);
	}
	else {
		dbg(DBG_PRINT, "(GRADING1C 5)\n");
		kthr->kt_cancelled = 1;
	}
}

/*
 * In this function, you will be modifying the run queue, which can
 * also be modified from an interrupt context. In order for thread
 * contexts and interrupt contexts to play nicely, you need to mask
 * all interrupts before reading or modifying the run queue and
 * re-enable interrupts when you are done. This is analagous to
 * locking a mutex before modifying a data structure shared between
 * threads. Masking interrupts is accomplished by setting the IPL to
 * high.
 *
 * Once you have masked interrupts, you need to remove a thread from
 * the run queue and switch into its context from the currently
 * executing context.
 *
 * If there are no threads on the run queue (assuming you do not have
 * any bugs), then all kernel threads are waiting for an interrupt
 * (for example, when reading from a block device, a kernel thread
 * will wait while the block device seeks). You will need to re-enable
 * interrupts and wait for one to occur in the hopes that a thread
 * gets put on the run queue from the interrupt context.
 *
 * The proper way to do this is with the intr_wait call. See
 * interrupt.h for more details on intr_wait.
 *
 * Note: When waiting for an interrupt, don't forget to modify the
 * IPL. If the IPL of the currently executing thread masks the
 * interrupt you are waiting for, the interrupt will never happen, and
 * your run queue will remain empty. This is very subtle, but
 * _EXTREMELY_ important.
 *
 * Note: Don't forget to set curproc and curthr. When sched_switch
 * returns, a different thread should be executing than the thread
 * which was executing when sched_switch was called.
 *
 * Note: The IPL is process specific.
 */
void
sched_switch(void)
{
	dbg(DBG_PRINT, "INFO : executing sched_switch\n");
	dbg(DBG_PRINT, "(GRADING1A)\n");
     /*NOT_YET_IMPLEMENTED("PROCS: sched_switch");*/
	/*save old interrupt level and set curr interrupt level to high, blocking interrupts:*/
	kthread_t *old_thread;
	uint8_t old_ipl = intr_getipl(); /*get and save current interrupt level*/
	intr_setipl(IPL_HIGH);

	while(sched_queue_empty(&kt_runq)) {
		dbg(DBG_PRINT, "INFO : waiting for interrupt. no threads in runQ\n");
		dbg(DBG_PRINT, "(GRADING1A)\n");
		intr_setipl(IPL_LOW);
		intr_wait();
		intr_setipl(IPL_HIGH);
	};

	/*save current thread to the old_thread: */
	old_thread = curthr;
	/* dequeue a thread from run queue:*/
	curthr = ktqueue_dequeue(&kt_runq);
	curthr->kt_state = KT_RUN;
	/*set current process to be current thread's process:*/
	curproc = curthr->kt_proc;
	/*switch contexts:*/
	context_switch(&(old_thread->kt_ctx), &(curthr->kt_ctx));
	/*make current thread context active: */
	/*context_make_active(&(curthr->kt_ctx)); we need to make the context active only once */
	/*re-enable interrupts again:*/
	intr_setipl(old_ipl); /*not sure about this as it might not be defined in the new threads context*/
	dbg(DBG_PRINT, "INFO : got the new thread for CPU %d\n", curproc->p_pid);
}

/*
 * Since we are modifying the run queue, we _MUST_ set the IPL to high
 * so that no interrupts happen at an inopportune moment.

 * Remember to restore the original IPL before you return from this
 * function. Otherwise, we will not get any interrupts after returning
 * from this function.
 *
 * Using intr_disable/intr_enable would be equally as effective as
 * modifying the IPL in this case. However, in some cases, we may want
 * more fine grained control, making modifying the IPL more
 * suitable. We modify the IPL here for consistency.
 */
void
sched_make_runnable(kthread_t *thr)
{
	dbg(DBG_PRINT, "INFO : executing sched_make_runnable\n");
	KASSERT(&kt_runq != thr->kt_wchan); /* make sure thread is not already in the runq */
	dbg(DBG_PRINT, "(GRADING1A 4.b)\n");
    /*NOT_YET_IMPLEMENTED("PROCS: sched_make_runnable");*/

	/*save old interrupt level and set curr interrupt level to high, blocking interrupts:*/
	uint8_t old_ipl = intr_getipl(); /*get and save current interrupt level*/
	intr_setipl(IPL_HIGH);
	/* set the thread state to runnable:*/
	thr->kt_state = KT_RUN;
	/* enqueue the thread to the kt_runq (runnable queue):*/
	ktqueue_enqueue(&kt_runq, thr);
	/*set the IPL to old:*/
	intr_setipl(old_ipl);
}
