# Trace-runqlat

Trace_irqoffv工具可以帮助我们排查由于中断被关闭导致的延迟抖动问题。但是这只是第一阶段可能遇到的问题。当我们将一个线程加入runqueue后，如果系统的负载很高，在runqueue中排在你前面的进程可能会由于执行很长时间（或许你会好奇怎么可能执行很长时间，难道不会抢占吗？还真可能出现这种情况。因为我们的kernel是不开抢占）导致最终runqueue latency很大。针对这种问题排查，我们开发一款新的排查工具**Run queue latency tracer。简称：trace-runqlat。**作用是记录被跟踪的进程在加入runqueue后，前面的每个线程执行的时间以及线程command等信息。

## 如何安装

安装 trace_runqlat 工具很简单，git clone代码后执行如下命令即可安装。

```bash
make -j8
make install
```

## 如何使用

安装 trace-runqlat工具成功后。会创建如下 **/proc/trace_runqlat** 目录。

```bash
ls /proc/trace_runqlat
distribution  pid  runqlat  threshold
```

/proc/trace_runqlat 目录下存在 4 个文件，分别：distribution, pid, runqlat和threshold。工具安装后，默认是打开状态，但是并没有trace任何线程，我们需要手动设置需要trace的线程pid。

##### 1. 跟踪特定pid线程

```
echo $pid > /proc/trace_runqlat/pid
```

##### 2. 关闭跟踪

```
echo -1 > /proc/trace_runqlat/pid
```

##### 3. 设置阈值

trace-runqlat只会针对延迟超过阈值的情况，记录runqueue前面的线程执行的时间情况。为了更高效的运作，我们有必要设定一个合理阈值。例如设置60ms的阈值：

```
echo 60000000 > /proc/trace_runqlat/threshold # 单位ns
```

如果需要查看当前设定的阈值，可执行如下命令：

```
cat /proc/trace_runqlat/threshold
```

##### 4. 查看线程runqueue latency分布

我们以直方图的形式展示被跟踪进程runqueue latency的分布情况。

```
cat /proc/trace_runqlat/distribution
```

你看到的信息展示如同下面这样：

```
     msecs      : count  distribution
     1 -> 1     : 0     |                                        |
     2 -> 3     : 0     |                                        |
     4 -> 7     : 0     |                                        |
     8 -> 15    : 0     |                                        |
    16 -> 31    : 0     |                                        |
    32 -> 63    : 68    |****************************************|
```

我们可以看到latency集中在[32, 63]毫秒，次数68次。

##### 5. 是谁在runqueue的前面

针对latency超过阈值的情况，我们会记录runqueue前面的线程执行情况。

Note: 必须关闭trace的情况下才能查看该文件信息。

```
cat /proc/trace_runqlat/runqlat
 latency(us): 35999 runqlen: 10
   COMM: loop7          PID: 3789453 RUNTIME(us):  4000
   COMM: loop2          PID: 3789448 RUNTIME(us):  4001
   COMM: loop4          PID: 3789450 RUNTIME(us):  3998
   COMM: loop1          PID: 3789447 RUNTIME(us):  3999
   COMM: loop3          PID: 3789449 RUNTIME(us):  4000
   COMM: loop8          PID: 3789454 RUNTIME(us):  3999
   COMM: loop9          PID: 3789455 RUNTIME(us):  4001
   COMM: kworker/0:2    PID: 3621088  RUNTIME(us):    3
   COMM: loop5          PID: 3789451 RUNTIME(us):  3994
   COMM: loop6          PID: 3789452 RUNTIME(us):  3999
```

我们可以看到runqueue latency是35999us。runqueue前面有10个进程。每个进程的执行时间加在一起差不多就是总的latency。
