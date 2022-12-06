// SPDX-License-Identifier: GPL-2.0
/*
 * Trace Run Queue Latency
 *
 * Copyright (C) 2020 Bytedance, Inc., Muchun Song
 *
 * The main authors of the trace qunqueue latency code are:
 *
 * Muchun Song <songmuchun@bytedance.com>
 */
#define pr_fmt(fmt) "runqlat: " fmt

#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/stacktrace.h>
#include <linux/timer.h>
#include <linux/tracepoint.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <trace/events/sched.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#include <linux/sched.h>
#else
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#endif

#define MAX_TRACE_ENTRIES		128
#define PER_TRACE_ENTRY_TASKS		16
#define MAX_TRACE_ENTRY_TASKS		\
	(MAX_TRACE_ENTRIES * PER_TRACE_ENTRY_TASKS)

#define THRESHOLD_DEFAULT		(20 * 1000 * 1000UL)

#define INVALID_PID			-1
#define INVALID_CPU			-1
#define PROBE_TRACEPOINTS		 4

#define LATENCY_HISTOGRAM_ENTRY		12

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#define DEFINE_PROC_ATTRIBUTE(name, __write)				\
	static int name##_open(struct inode *inode, struct file *file)	\
	{								\
		return single_open(file, name##_show, PDE_DATA(inode));	\
	}								\
									\
	static const struct file_operations name##_fops = {		\
		.owner		= THIS_MODULE,				\
		.open		= name##_open,				\
		.read		= seq_read,				\
		.write		= __write,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	}
#else
#define DEFINE_PROC_ATTRIBUTE(name, __write)				\
	static int name##_open(struct inode *inode, struct file *file)	\
	{								\
		return single_open(file, name##_show, PDE_DATA(inode));	\
	}								\
									\
	static const struct proc_ops name##_fops = {			\
		.proc_open	= name##_open,				\
		.proc_read	= seq_read,				\
		.proc_write	= __write,				\
		.proc_lseek	= seq_lseek,				\
		.proc_release	= single_release,			\
	}
#endif /* LINUX_VERSION_CODE */

#define DEFINE_PROC_ATTRIBUTE_RW(name)					\
	static ssize_t name##_write(struct file *file,			\
				    const char __user *buf,		\
				    size_t count, loff_t *ppos)		\
	{								\
		return name##_store(PDE_DATA(file_inode(file)), buf,	\
				    count);				\
	}								\
	DEFINE_PROC_ATTRIBUTE(name, name##_write)

#define DEFINE_PROC_ATTRIBUTE_RO(name)	\
	DEFINE_PROC_ATTRIBUTE(name, NULL)

/**
 * If we call register_trace_sched_{wakeup,wakeup_new,switch,migrate_task}()
 * directly in a kernel module, the compiler will complain about undefined
 * symbol of __tracepoint_sched_{wakeup, wakeup_new, switch, migrate_task}
 * because the kernel do not export the tracepoint symbol. Here is a workaround
 * via for_each_kernel_tracepoint() to lookup the tracepoint and save.
 */
struct tracepoints_probe {
	struct tracepoint *tps[PROBE_TRACEPOINTS];
	const char *tp_names[PROBE_TRACEPOINTS];
	void *tp_probes[PROBE_TRACEPOINTS];
	void *priv;
	int num_initalized;
};

struct task_entry {
	u64 runtime;
	pid_t pid;
	char comm[TASK_COMM_LEN];
};

struct trace_entry {
	u64 latency;
	unsigned int nr_tasks;
	struct task_entry *entries;
};

struct runqlat_info {
	int cpu;		/* The target CPU */
	pid_t pid;		/* Trace this pid only */
	u64 rq_start;
	u64 run_start;
	u64 threshold;
	struct task_struct *curr;
	unsigned long latency_hist[LATENCY_HISTOGRAM_ENTRY];

	unsigned int nr_trace;
	struct trace_entry *trace_entries;

	unsigned int nr_task;
	struct task_entry *task_entries;

	arch_spinlock_t lock;
};

static struct runqlat_info runqlat_info = {
	.pid		= INVALID_PID,
	.cpu		= INVALID_CPU,
	.threshold	= THRESHOLD_DEFAULT,
	.lock		= __ARCH_SPIN_LOCK_UNLOCKED,
};

static void probe_sched_wakeup(void *priv, struct task_struct *p)
{
	struct runqlat_info *info = priv;

	if (p->pid != info->pid)
		return;

	/* interrupts should be off from try_to_wake_up() */
	arch_spin_lock(&info->lock);
	if (unlikely(p->pid != info->pid)) {
		arch_spin_unlock(&info->lock);
		return;
	}

	info->rq_start = local_clock();
	info->run_start = info->rq_start;
	info->cpu = task_cpu(p);
	arch_spin_unlock(&info->lock);
}

static inline void runqlat_info_reset(struct runqlat_info *info)
{
	info->rq_start = 0;
	info->run_start = 0;
	info->cpu = INVALID_CPU;
	info->curr = NULL;
}

/* Must be called with @info->lock held */
static void record_task(struct runqlat_info *info, struct task_struct *p,
			u64 runtime)
	__must_hold(&info->lock)
{
	struct task_entry *task;
	struct trace_entry *trace;

	task = info->task_entries + info->nr_task;
	trace = info->trace_entries + info->nr_trace;

	if (trace->nr_tasks == 0)
		trace->entries = task;
	WARN_ON_ONCE(trace->entries != task - trace->nr_tasks);
	trace->nr_tasks++;

	task->pid = p->pid;
	task->runtime = runtime;
	strncpy(task->comm, p->comm, TASK_COMM_LEN);

	info->nr_task++;
	if (unlikely(info->nr_task >= MAX_TRACE_ENTRY_TASKS)) {
		pr_info("BUG: MAX_TRACE_ENTRY_TASKS too low!");
		runqlat_info_reset(info);
		/* Force disable trace */
		info->pid = INVALID_PID;
	}
}

static inline void latency_histogram_store(struct runqlat_info *info, u64 delta)
{
	int index = -1;

	delta /= 1000000UL;
	do {
		index++;
		delta >>= 1;
	} while (delta > 0);

	if (unlikely(index >= LATENCY_HISTOGRAM_ENTRY))
		index = LATENCY_HISTOGRAM_ENTRY - 1;

	info->latency_hist[index]++;
}

/* Must be called with @info->lock held */
static bool record_task_commit(struct runqlat_info *info, u64 latency)
	__must_hold(&info->lock)
{
	struct trace_entry *trace;

	latency_histogram_store(info, latency);
	trace = info->trace_entries + info->nr_trace;
	if (trace->nr_tasks == 0)
		return false;

	if (latency >= info->threshold) {
		trace->latency = latency;
		info->nr_trace++;
		if (unlikely(info->nr_trace >= MAX_TRACE_ENTRIES)) {
			pr_info("BUG: MAX_TRACE_ENTRIES too low!");
			runqlat_info_reset(info);
			/* Force disable trace */
			info->pid = INVALID_PID;
		}
	} else {
		info->nr_task -= trace->nr_tasks;
		trace->nr_tasks = 0;
		trace->entries = NULL;
	}

	return true;
}

/* interrupts should be off from __schedule() */
static void probe_sched_switch(void *priv, bool preempt,
			       struct task_struct *prev,
			       struct task_struct *next)
{
	struct runqlat_info *info = priv;
	int cpu = smp_processor_id();
	arch_spinlock_t *lock = &info->lock;

	if (info->pid == INVALID_PID)
		return;

	if (info->cpu != INVALID_CPU && info->cpu != cpu)
		return;

	if (READ_ONCE(info->cpu) == INVALID_CPU) {
		if (READ_ONCE(info->pid) != prev->pid ||
		    prev->state != TASK_RUNNING)
			return;

		arch_spin_lock(lock);
		/* We could race with grabbing lock */
		if (unlikely(info->cpu != INVALID_CPU ||
			     info->pid != prev->pid)) {
			arch_spin_unlock(lock);
			return;
		}
		info->rq_start = cpu_clock(cpu);
		info->run_start = info->rq_start;
		info->cpu = task_cpu(prev);

		/* update curr for migrate task probe using*/
		if (!is_idle_task(next))
			info->curr = next;
		arch_spin_unlock(lock);
	} else {
		u64 now;

		if (unlikely(READ_ONCE(info->cpu) != cpu ||
			     READ_ONCE(info->pid) == INVALID_PID))
			return;

		arch_spin_lock(lock);
		/* We could race with grabbing lock */
		if (unlikely(info->cpu != cpu || info->pid == INVALID_PID)) {
			arch_spin_unlock(lock);
			return;
		}

		/* update curr for migrate task probe using*/
		if (!is_idle_task(next))
			info->curr = next;

		now = cpu_clock(cpu);
		if (info->pid == next->pid) {
			if (info->run_start)
				record_task(info, prev, now - info->run_start);
			record_task_commit(info, now - info->rq_start);
		} else if (info->pid == prev->pid) {
			if (prev->state == TASK_RUNNING) {
				info->rq_start = now;
				info->run_start = now;
			} else {
				runqlat_info_reset(info);
			}
		} else {
			if (info->run_start)
				record_task(info, prev, now - info->run_start);
			info->run_start = now;
		}
		arch_spin_unlock(lock);
	}
}

static void probe_sched_migrate_task(void *priv, struct task_struct *p, int cpu)
{
	u64 now;
	struct runqlat_info *info = priv;
	struct task_struct *curr;

	if (p->pid != info->pid || info->cpu == INVALID_CPU)
		return;

	/* interrupts should be off from set_task_cpu() */
	arch_spin_lock(&info->lock);
	if (unlikely(p->pid != info->pid || info->cpu == INVALID_CPU))
		goto unlock;

	now = local_clock();
	curr = info->curr;
	if (curr) {
		get_task_struct(curr);
		if (info->run_start)
			record_task(info, curr, now - info->run_start);
		put_task_struct(curr);
	}

	info->cpu = cpu;
	info->run_start = now;
unlock:
	arch_spin_unlock(&info->lock);
}

static struct tracepoints_probe tps_probe = {
	.tp_names = {
		"sched_wakeup",
		"sched_wakeup_new",
		"sched_switch",
		"sched_migrate_task",
	},
	.tp_probes = {
		probe_sched_wakeup,
		probe_sched_wakeup,
		probe_sched_switch,
		probe_sched_migrate_task,
	},
	.priv = &runqlat_info,
};

static inline bool is_tracepoint_lookup_success(struct tracepoints_probe *tps)
{
	return tps->num_initalized == PROBE_TRACEPOINTS;
}

static void __init tracepoint_lookup(struct tracepoint *tp, void *priv)
{
	int i;
	struct tracepoints_probe *tps = priv;

	if (is_tracepoint_lookup_success(tps))
		return;

	for (i = 0; i < ARRAY_SIZE(tps->tp_names); i++) {
		if (tps->tps[i] || strcmp(tp->name, tps->tp_names[i]))
			continue;
		tps->tps[i] = tp;
		tps->num_initalized++;
	}
}

static int trace_pid_show(struct seq_file *m, void *ptr)
{
	struct runqlat_info *info = m->private;

	seq_printf(m, "%d\n", info->pid);

	return 0;
}

static ssize_t trace_pid_store(void *priv, const char __user *buf, size_t count)
{
	int pid;
	struct runqlat_info *info = priv;

	if (kstrtoint_from_user(buf, count, 0, &pid))
		return -EINVAL;

	if (info->pid != INVALID_PID && pid != INVALID_PID)
		return -EPERM;

	local_irq_disable();
	arch_spin_lock(&info->lock);
	if (info->pid == pid)
		goto unlock;

	if (pid != INVALID_PID) {
		int i;

		info->nr_trace = 0;
		info->nr_task = 0;
		memset(info->trace_entries, 0,
		       MAX_TRACE_ENTRIES * sizeof(struct trace_entry) +
		       MAX_TRACE_ENTRY_TASKS * sizeof(struct task_entry));

		for (i = 0; i < LATENCY_HISTOGRAM_ENTRY; i++)
			info->latency_hist[i] = 0;
	}
	runqlat_info_reset(info);
	smp_wmb();
	info->pid = pid;
unlock:
	arch_spin_unlock(&info->lock);
	local_irq_enable();

	return count;
}

DEFINE_PROC_ATTRIBUTE_RW(trace_pid);

static int threshold_show(struct seq_file *m, void *ptr)
{
	struct runqlat_info *info = m->private;

	seq_printf(m, "%llu\n", info->threshold);

	return 0;
}

static ssize_t threshold_store(void *priv, const char __user *buf, size_t count)
{
	unsigned long threshold;
	struct runqlat_info *info = priv;

	if (kstrtoul_from_user(buf, count, 0, &threshold))
		return -EINVAL;

	info->threshold = threshold;

	return count;
}

DEFINE_PROC_ATTRIBUTE_RW(threshold);

static int runqlat_show(struct seq_file *m, void *ptr)
{
	int i, j;
	struct runqlat_info *info = m->private;

	if (info->pid == INVALID_PID)
		return -EPERM;

	local_irq_disable();
	arch_spin_lock(&info->lock);
	for (i = 0; i < info->nr_trace; i++) {
		struct trace_entry *entry = info->trace_entries + i;

		seq_printf(m, "%*clatency(us): %llu runqlen: %d\n", 2, ' ',
			   entry->latency / 1000, entry->nr_tasks);

		for (j = 0; j < entry->nr_tasks; j++) {
			struct task_entry *task = entry->entries + j;

			seq_printf(m, "%*cCOMM: %-16s PID: %-8d RUNTIME(us): %6llu\n",
				   6, ' ', task->comm, task->pid,
				   task->runtime / 1000);
		}

		seq_putc(m, '\n');
	}

	arch_spin_unlock(&info->lock);
	local_irq_enable();

	return 0;
}

DEFINE_PROC_ATTRIBUTE_RO(runqlat);

#define NUMBER_CHARACTER	40

static bool histogram_show(struct seq_file *m, const char *header,
			   const unsigned long *hist, unsigned long size,
			   unsigned int factor)
{
	int i, zero_index = 0;
	unsigned long count_max = 0;

	for (i = 0; i < size; i++) {
		unsigned long count = hist[i];

		if (count > count_max)
			count_max = count;

		if (count)
			zero_index = i + 1;
	}
	if (count_max == 0)
		return false;

	/* print header */
	if (header)
		seq_printf(m, "%s\n", header);
	seq_printf(m, "%*c%s%*c : %-9s %s\n", 9, ' ', "msecs", 10, ' ', "count",
		   "distribution");

	for (i = 0; i < zero_index; i++) {
		int num;
		int scale_min, scale_max;
		char str[NUMBER_CHARACTER + 1];

		scale_max = 2 << i;
		scale_min = unlikely(i == 0) ? 1 : scale_max / 2;

		num = hist[i] * NUMBER_CHARACTER / count_max;
		memset(str, '*', num);
		memset(str + num, ' ', NUMBER_CHARACTER - num);
		str[NUMBER_CHARACTER] = '\0';

		seq_printf(m, "%10d -> %-10d : %-8lu |%s|\n",
			   scale_min * factor, scale_max * factor - 1,
			   hist[i], str);
	}

	return true;
}

static int distribution_show(struct seq_file *m, void *ptr)
{
	int i;
	unsigned long hist[LATENCY_HISTOGRAM_ENTRY];
	struct runqlat_info *info = m->private;

	for (i = 0; i < LATENCY_HISTOGRAM_ENTRY; i++)
		hist[i] = info->latency_hist[i];

	histogram_show(m, NULL, hist, LATENCY_HISTOGRAM_ENTRY, 1);

	return 0;
}

DEFINE_PROC_ATTRIBUTE_RO(distribution);

static int __init trace_runqlat_init(void)
{
	int i;
	void *buf;
	int ret = -ENOMEM;
	struct tracepoints_probe *tps = &tps_probe;
	struct proc_dir_entry *parent_dir;
	struct runqlat_info *info = &runqlat_info;

	buf = vzalloc(MAX_TRACE_ENTRIES * sizeof(struct trace_entry) +
		      MAX_TRACE_ENTRY_TASKS * sizeof(struct task_entry));
	if (!buf)
		return -ENOMEM;
	info->trace_entries = buf;
	info->task_entries = (void *)(info->trace_entries + MAX_TRACE_ENTRIES);

	parent_dir = proc_mkdir("trace_runqlat", NULL);
	if (!parent_dir)
		goto free_buf;

	if (!proc_create_data("pid", 0644, parent_dir, &trace_pid_fops, info))
		goto remove_proc;

	if (!proc_create_data("threshold", 0644, parent_dir, &threshold_fops,
			      info))
		goto remove_proc;

	if (!proc_create_data("runqlat", 0, parent_dir, &runqlat_fops, info))
		goto remove_proc;

	if (!proc_create_data("distribution", 0, parent_dir, &distribution_fops,
			      info))
		goto remove_proc;

	/* Lookup for the tracepoint that we needed */
	for_each_kernel_tracepoint(tracepoint_lookup, tps);

	if (!is_tracepoint_lookup_success(tps))
		goto remove_proc;

	for (i = 0; i < PROBE_TRACEPOINTS; i++) {
		ret = tracepoint_probe_register(tps->tps[i], tps->tp_probes[i],
						tps->priv);
		if (ret) {
			pr_err("sched trace: can not activate tracepoint "
			       "probe to %s\n", tps->tp_names[i]);
			while (i--)
				tracepoint_probe_unregister(tps->tps[i],
							    tps->tp_probes[i],
							    tps->priv);
			goto remove_proc;
		}
	}

	return 0;
remove_proc:
	remove_proc_subtree("trace_runqlat", NULL);
free_buf:
	vfree(buf);

	return ret;
}

static void __exit trace_runqlat_exit(void)
{
	int i;
	struct tracepoints_probe *tps = &tps_probe;
	struct runqlat_info *info = &runqlat_info;

	for (i = 0; i < PROBE_TRACEPOINTS; i++)
		tracepoint_probe_unregister(tps->tps[i], tps->tp_probes[i],
					    tps->priv);

	tracepoint_synchronize_unregister();
	remove_proc_subtree("trace_runqlat", NULL);
	vfree(info->trace_entries);
}

module_init(trace_runqlat_init);
module_exit(trace_runqlat_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Muchun Song <songmuchun@bytedance.com>");
