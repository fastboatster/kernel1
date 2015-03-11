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

#include "types.h"
#include "globals.h"
#include "kernel.h"

#include "util/gdb.h"
#include "util/init.h"
#include "util/debug.h"
#include "util/string.h"
#include "util/printf.h"

#include "mm/mm.h"
#include "mm/page.h"
#include "mm/pagetable.h"
#include "mm/pframe.h"

#include "vm/vmmap.h"
#include "vm/shadowd.h"
#include "vm/shadow.h"
#include "vm/anon.h"

#include "main/acpi.h"
#include "main/apic.h"
#include "main/interrupt.h"
#include "main/gdt.h"

#include "proc/sched.h"
#include "proc/proc.h"
#include "proc/kthread.h"

#include "drivers/dev.h"
#include "drivers/blockdev.h"
#include "drivers/disk/ata.h"
#include "drivers/tty/virtterm.h"
#include "drivers/pci.h"

#include "api/exec.h"
#include "api/syscall.h"

#include "fs/vfs.h"
#include "fs/vnode.h"
#include "fs/vfs_syscall.h"
#include "fs/fcntl.h"
#include "fs/stat.h"

#include "test/kshell/kshell.h"
#include "errno.h"

GDB_DEFINE_HOOK(boot)
GDB_DEFINE_HOOK(initialized)
GDB_DEFINE_HOOK(shutdown)

static void       hard_shutdown(void);
static void      *bootstrap(int arg1, void *arg2);
static void      *idleproc_run(int arg1, void *arg2);
static kthread_t *initproc_create(void);
static void      *initproc_run(int arg1, void *arg2);

static context_t bootstrap_context;
static int gdb_wait = GDBWAIT;

/**
 * This is the first real C function ever called. It performs a lot of
 * hardware-specific initialization, then creates a pseudo-context to
 * execute the bootstrap function in.
 */
void
kmain()
{
        GDB_CALL_HOOK(boot);

        dbg_init();
        dbgq(DBG_CORE, "Kernel binary:\n");
        dbgq(DBG_CORE, "  text: 0x%p-0x%p\n", &kernel_start_text, &kernel_end_text);
        dbgq(DBG_CORE, "  data: 0x%p-0x%p\n", &kernel_start_data, &kernel_end_data);
        dbgq(DBG_CORE, "  bss:  0x%p-0x%p\n", &kernel_start_bss, &kernel_end_bss);

        page_init();

        pt_init();
        slab_init();
        pframe_init();

        acpi_init();
        apic_init();
	      pci_init();
        intr_init();

        gdt_init();

        /* initialize slab allocators */
#ifdef __VM__
        anon_init();
        shadow_init();
#endif
        vmmap_init();
        proc_init();
        kthread_init();

#ifdef __DRIVERS__
        bytedev_init();
        blockdev_init();
#endif

        void *bstack = page_alloc();
        pagedir_t *bpdir = pt_get();
        KASSERT(NULL != bstack && "Ran out of memory while booting.");
        /* This little loop gives gdb a place to synch up with weenix.  In the
         * past the weenix command started qemu was started with -S which
         * allowed gdb to connect and start before the boot loader ran, but
         * since then a bug has appeared where breakpoints fail if gdb connects
         * before the boot loader runs.  See
         *
         * https://bugs.launchpad.net/qemu/+bug/526653
         *
         * This loop (along with an additional command in init.gdb setting
         * gdb_wait to 0) sticks weenix at a known place so gdb can join a
         * running weenix, set gdb_wait to zero  and catch the breakpoint in
         * bootstrap below.  See Config.mk for how to set GDBWAIT correctly.
         *
         * DANGER: if GDBWAIT != 0, and gdb is not running, this loop will never
         * exit and weenix will not run.  Make SURE the GDBWAIT is set the way
         * you expect.
         */
        while (gdb_wait) ;
        context_setup(&bootstrap_context, bootstrap, 0, NULL, bstack, PAGE_SIZE, bpdir);
        context_make_active(&bootstrap_context);

        panic("\nReturned to kmain()!!!\n");
}

/**
 * Clears all interrupts and halts, meaning that we will never run
 * again.
 */
static void
hard_shutdown()
{
#ifdef __DRIVERS__
        vt_print_shutdown();
#endif
        __asm__ volatile("cli; hlt");
}

/**
 * This function is called from kmain, however it is not running in a
 * thread context yet. It should create the idle process which will
 * start executing idleproc_run() in a real thread context.  To start
 * executing in the new process's context call context_make_active(),
 * passing in the appropriate context. This function should _NOT_
 * return.
 *
 * Note: Don't forget to set curproc and curthr appropriately.
 *
 * @param arg1 the first argument (unused)
 * @param arg2 the second argument (unused)
 */
static void *
bootstrap(int arg1, void *arg2)
{
	/*
	 * PID  = 0 ; idle_proc
	 * PID = 1; init_proc
	 * PID = 2; pageoutd
	 */
		dbg(DBG_PRINT, "INFO : executing bootstrap\n");
		dbg(DBG_PRINT, "(GRADING1A)\n");
        /* necessary to finalize page table information */
        pt_template_init();

        /* idle process creation */
        proc_t* idle_proc = proc_create("Idle");
        KASSERT(NULL != idle_proc);
        KASSERT(PID_IDLE == idle_proc->p_pid); /* newly create process PID should match with IDLE_PID since its the first process that got created */
        kthread_t* idle_thr = kthread_create(idle_proc, idleproc_run, NULL, NULL);
        KASSERT(NULL != idle_thr);
       /* dbg(DBG_PRINT, "(GRADING1A 1.a)\n");dbg call for idleproc thread creation*/
        curproc = idle_proc; /* set current process */
        KASSERT(NULL != curproc);
        dbg(DBG_PRINT, "(GRADING1A 1.a)\n"); /*dbg call for successful idleproc creation*/
        dbg(DBG_PRINT, "INFO : Idle process created \n");
        curthr = idle_thr; /* set current thread */
        KASSERT(NULL != curthr);
        dbg(DBG_PRINT, "(GRADING1A 1.a)\n");
        dbg(DBG_PRINT, "INFO : Idle thread created \n");
        KASSERT(NULL != &(idle_thr->kt_ctx));
        KASSERT(PID_IDLE == curproc->p_pid);
        dbg(DBG_PRINT, "(GRADING1A 1.a)\n");
        context_make_active(&(idle_thr->kt_ctx)); /* to make idle execute right away */



        /* NOT_YET_IMPLEMENTED("PROCS: bootstrap"); */
        panic("weenix returned to bootstrap()!!! BAD!!!\n");
        return NULL;
}

/**
 * Once we're inside of idleproc_run(), we are executing in the context of the
 * first process-- a real context, so we can finally begin running
 * meaningful code.
 *
 * This is the body of process 0. It should initialize all that we didn't
 * already initialize in kmain(), launch the init process (initproc_run),
 * wait for the init process to exit, then halt the machine.
 *
 * @param arg1 the first argument (unused)
 * @param arg2 the second argument (unused)
 */
static void *
idleproc_run(int arg1, void *arg2)
{
        int status;
        pid_t child;

        /* create init proc */
        kthread_t *initthr = initproc_create();
        init_call_all();
        GDB_CALL_HOOK(initialized);

        /* Create other kernel threads (in order) */

#ifdef __VFS__
        /* Once you have VFS remember to set the current working directory
         * of the idle and init processes */
        NOT_YET_IMPLEMENTED("VFS: idleproc_run");

        /* Here you need to make the null, zero, and tty devices using mknod */
        /* You can't do this until you have VFS, check the include/drivers/dev.h
         * file for macros with the device ID's you will need to pass to mknod */
        NOT_YET_IMPLEMENTED("VFS: idleproc_run");
#endif

        /* Finally, enable interrupts (we want to make sure interrupts
         * are enabled AFTER all drivers are initialized) */
        intr_enable();

        /* Run initproc */
        sched_make_runnable(initthr);
        /* Now wait for it */
        child = do_waitpid(-1, 0, &status);
        KASSERT(PID_INIT == child);

#ifdef __MTP__
        kthread_reapd_shutdown();
#endif


#ifdef __SHADOWD__
        /* wait for shadowd to shutdown */
        shadowd_shutdown();
#endif

#ifdef __VFS__
        /* Shutdown the vfs: */
        dbg_print("weenix: vfs shutdown...\n");
        vput(curproc->p_cwd);
        if (vfs_shutdown())
                panic("vfs shutdown FAILED!!\n");

#endif

        /* Shutdown the pframe system */
#ifdef __S5FS__
        pframe_shutdown();
#endif

        dbg_print("\nweenix: halted cleanly!\n");
        GDB_CALL_HOOK(shutdown);
        hard_shutdown();
        return NULL;
}

/**
 * This function, called by the idle process (within 'idleproc_run'), creates the
 * process commonly refered to as the "init" process, which should have PID 1.
 *
 * The init process should contain a thread which begins execution in
 * initproc_run().
 *
 * @return a pointer to a newly created thread which will execute
 * initproc_run when it begins executing
 */
static kthread_t *
initproc_create(void)
{
	/* NOT_YET_IMPLEMENTED("PROCS: initproc_create");
	 * return NULL;
	 */
			dbg(DBG_PRINT, "INFO : executing initproc_create \n");
			dbg(DBG_PRINT, "(GRADING1A)\n");

	        proc_t *init_proc=proc_create("Init");
	        KASSERT(NULL != init_proc);		/*Asserting that init_proc is not null*/
	        dbg(DBG_PRINT, "(GRADING1A 1.b)\n");
	        KASSERT(init_proc->p_pid == PID_INIT); /* init_proc should have pid 1*/
	        dbg(DBG_PRINT, "(GRADING1A 1.b)\n");
	        dbg(DBG_PRINT, "INFO : Init process created \n");
	        kthread_t *init_thr=kthread_create(init_proc,initproc_run,NULL,NULL);
	        KASSERT(NULL != init_thr);
	        dbg(DBG_PRINT, "(GRADING1A 1.b)\n");
	        dbg(DBG_PRINT, "INFO : Init thread created \n");
	        return init_thr;
}

/**
 * The init thread's function changes depending on how far along your Weenix is
 * developed. Before VM/FI, you'll probably just want to have this run whatever
 * tests you've written (possibly in a new process). After VM/FI, you'll just
 * exec "/sbin/init".
 *
 * Both arguments are unused.
 *
 * @param arg1 the first argument (unused)
 * @param arg2 the second argument (unused)
 */
extern void *faber_thread_test(int, void*);
static int my_faber_thread_test(kshell_t* kshell, int argc, char** argv) {
	dbg(DBG_PRINT, "INFO : executing faber_thread_test\n");
	dbg(DBG_PRINT, "(GRADING1C)\n");
	proc_t* new_faber_proc = proc_create("faber_test");
	KASSERT(NULL != new_faber_proc);
	kthread_t *new_faber_thr = kthread_create(new_faber_proc, faber_thread_test, 1, NULL);
	KASSERT(NULL != new_faber_thr);
	dbg(DBG_PRINT, "faber_test process created with pid %d\n", new_faber_proc->p_pid);
	sched_make_runnable(new_faber_thr);
	while(do_waitpid(-1, 0, NULL) != -ECHILD);
	return NULL;
}
extern void *sunghan_test(int, void*);
static int my_sunghan_test(kshell_t* kshell, int argc, char** argv){
	dbg(DBG_PRINT, "INFO: executing sunghan test\n");
	dbg(DBG_PRINT, "(GRADING1D 1)\n");
	proc_t *new_sunghan_test = proc_create("sunghan_test");
	KASSERT(NULL != new_sunghan_test);
	kthread_t *new_sunghan_thr = kthread_create(new_sunghan_test, sunghan_test, 1, NULL);
	KASSERT(NULL != new_sunghan_thr);
	dbg(DBG_PRINT, "sunghun_test process created with pid %d\n", new_sunghan_test->p_pid);
	sched_make_runnable(new_sunghan_thr);
	while(do_waitpid(-1, 0, NULL) != -ECHILD);
	return NULL;
}
extern void *sunghan_deadlock_test(int, void*);
static int my_sunghan_deadlock_test(kshell_t* kshell, int argc, char** argv){
	dbg(DBG_PRINT, "INFO : executing sunghan deadlock test\n");
	dbg(DBG_PRINT, "(GRADING1D 2)\n");
	proc_t *new_sunghan_deadlock_test = proc_create("sunghan_deadlock_test");
	KASSERT(NULL != new_sunghan_deadlock_test);
	kthread_t *new_sunghan_deadlock_thr = kthread_create(new_sunghan_deadlock_test, sunghan_deadlock_test, 1, NULL);
	KASSERT(NULL != new_sunghan_deadlock_thr);
	dbg(DBG_PRINT, "sunghun_deadlock_test process created with pid %d\n", new_sunghan_deadlock_test->p_pid);
	sched_make_runnable(new_sunghan_deadlock_thr);
	while(do_waitpid(-1, 0, NULL) != -ECHILD);
	return NULL;
}
static void *
initproc_run(int arg1, void *arg2)
{
	dbg(DBG_PRINT, "INFO : executing initproc_run\n");
	dbg(DBG_PRINT, "(GRADING1A)\n");
    /* NOT_YET_IMPLEMENTED("PROCS: initproc_run");*/
#ifdef __DRIVERS__
	dbg(DBG_PRINT, "(GRADING1B)\n");

	kshell_add_command("faber_test", my_faber_thread_test, "Run faber_thread_test()");
	kshell_add_command("sunghan_test", my_sunghan_test, "Run sunghan_test().");
	kshell_add_command("sunghan_deadlock", my_sunghan_deadlock_test, "Run sunghan_deadlock_test().");
    kshell_t *kshell = kshell_create(0);
    if (NULL == kshell) panic("init: Couldn't create kernel shell\n");
    while (kshell_execute_next(kshell));
    kshell_destroy(kshell);
#else
    my_faber_thread_test(NULL, NULL, NULL);
    my_sunghan_test(NULL, NULL, NULL);
    my_sunghan_deadlock_test(NULL, NULL, NULL);
#endif
	/* waits for all children to die */
	while(do_waitpid(-1, 0, NULL) != -ECHILD);

    return NULL;

}
