/* Minimal PID 1 for the QEMU-boot runtime CI job (see
 * .github/workflows/qemu-boot-test.yml) - actually boots a kernel,
 * insmod's av.ko, and confirms EICAR detection fires for real, unlike
 * build-matrix.yml's compile-only testing. No busybox, no shell -
 * just enough libc + a couple of direct syscalls to mount what's
 * needed, load the module, exec a clean file and an EICAR file, check
 * the results against dmesg, print one final PASS/FAIL line to the
 * serial console, and power off. Statically linked.
 *
 * See also cold_launcher.c (same directory) - a dedicated companion
 * binary this one execs partway through, specifically to reproduce
 * and track a real, documented gap in av.ko's kprobe hook (cold
 * userspace pages in atomic context - see its own header comment,
 * and av/main.c's handler_pre()).
 *
 * All output goes through outmsg() (vsnprintf into a buffer + a raw
 * write(2) to fd 1) rather than stdio - printf()+fflush() was tried
 * first and its output never reached the serial console (kernel
 * printk output appeared fine; only userspace stdio output was
 * lost), for reasons not fully root-caused. write() sidesteps
 * whatever that was rather than chasing it further.
 *
 * Runs in one of two modes:
 *   - argv[1] == "--clean-marker": immediately exit(42). This is what
 *     gets exec'd as the "definitely not malicious" test case - no
 *     separate coreutils/busybox binary needed, we just re-exec
 *     ourselves.
 *   - no args (PID 1): the actual init/test-runner logic below.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define EICAR                                                                \
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

/* What the cold-pathname case near the end of main() asserts - phrased
 * as a property of THIS HARNESS, deliberately, rather than of the gap
 * in av/main.c.
 *
 * That case runs cold_launcher.c, which execve()s /tmp/eicar_cold.com
 * from a pathname page it guarantees is cold: the bytes live in a
 * fresh file-backed mapping (mmap, never faulted, MADV_DONTNEED'd
 * right before execve) rather than in .rodata next to .text, so
 * fault-around cannot pull them in and the kprobe handler's atomic
 * strncpy_from_user() genuinely sees a non-resident page. See
 * cold_launcher.c's own header comment for the mechanism, and issue
 * #2 for the gap itself. Measured: the bypass reproduces here - the
 * cold exec survives with cold_launcher's own exit code 1 and no
 * detection kill line in dmesg, while the warm-path EICAR check
 * above still detects and kills normally (so this is the harness
 * demonstrating the gap, not a detection regression). Verified
 * locally on 7.2.2 under TCG; the CI kernel matrix re-checks it on
 * every push.
 *
 * It now gates on what it can actually observe:
 *
 *   0 = the bypass reproduces here and the cold exec survives.
 *       Current, measured. If that stops being true, either this
 *       harness regressed (the page is no longer cold) or the #2
 *       gap was actually fixed - both need a human, neither should
 *       be a printed line nobody reads.
 *   1 = the cold exec IS detected and killed here. Set this only
 *       with evidence, and update #2 to match.
 *
 * Both branches compile either way - a plain `if`, not an `#if`, so
 * the inactive one cannot bit-rot before the day it is needed. */
#define AV_EXPECT_COLD_EXEC_DETECTED 0

static void outmsg(const char *fmt, ...) {
  static char buf[65536];
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0)
    return;
  if ((size_t)n >= sizeof(buf))
    n = sizeof(buf) - 1;

  /* A short write here used to be silently discarded, which on a tty
   * under load loses the tail of a message (and the dmesg dumps below
   * are the largest writes this program makes). Loop until the whole
   * buffer is handed to the kernel; drain_console() is what then gets
   * it out of the UART. */
  {
    size_t remaining = (size_t)n;
    const char *p = buf;

    while (remaining > 0) {
      ssize_t w = write(1, p, remaining);
      if (w < 0) {
        if (errno == EINTR)
          continue;
        return; /* nothing useful left to do - this IS the error path */
      }
      if (w == 0)
        return;
      p += w;
      remaining -= (size_t)w;
    }
  }
}

/* write(2) returning means the bytes reached the tty's output queue,
 * NOT that the UART has shifted them out. reboot(RB_POWER_OFF)
 * discards whatever is still sitting in the pl011 TX FIFO, so a
 * message written immediately before poweroff can be lost outright -
 * which is exactly how a fully-passing run lost its "QEMU_TEST: PASS"
 * line on the 6.12.107 leg of PR #44 while the identical commit passed
 * on the push run of the same workflow two minutes earlier - every
 * assertion had already printed, the verdict was the only thing
 * missing. Kernel printks survive this because the console write path
 * polls the UART directly instead of queueing, which is why
 * "reboot: Power down" still made it into that log and PASS did not.
 *
 * sync() does not help: it flushes filesystems, not ttys. tcdrain()
 * is the call that blocks until the output has actually been
 * transmitted. The nanosleep() after it is a cheap backstop for the
 * case where fd 1 is not a tty at all (tcdrain -> ENOTTY), so a
 * future harness that redirects output somewhere else does not
 * silently regress to losing its verdict. */
static void drain_console(void) {
  while (tcdrain(1) != 0) {
    if (errno == EINTR)
      continue;
    break;
  }
  {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000L};
    nanosleep(&ts, NULL);
  }
}

/* Single exit path for every verdict in this file - drain first, then
 * sync, then power off. Nothing here should call reboot() directly. */
static void poweroff_now(void) {
  drain_console();
  sync();
  reboot(RB_POWER_OFF);
}

static void die(const char *msg) __attribute__((noreturn));
static void die(const char *msg) {
  outmsg("QEMU_TEST: FAIL: %s: %s\n", msg, strerror(errno));
  poweroff_now();
  _exit(1);
}

static void pass_and_poweroff(void) {
  outmsg("QEMU_TEST: PASS\n");
  poweroff_now();
  _exit(0);
}

static void write_file(const char *path, const char *content) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (fd < 0)
    die("open for write");
  if (write(fd, content, strlen(content)) < 0)
    die("write");
  close(fd);
}

/* Writes `n` copies of byte `c` to `path` (0700, like write_file()).
 * Used for the #51 slow-scan fixture below: an 8KB file of identical
 * bytes is content only a calibration rule cares about, and a fixed
 * byte keeps the staging time independent of guest entropy. */
static void write_repeated(const char *path, char c, size_t n) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  char chunk[4096];
  size_t done = 0;

  if (fd < 0)
    die("open for repeated write");
  memset(chunk, c, sizeof(chunk));
  while (done < n) {
    size_t want = n - done > sizeof(chunk) ? sizeof(chunk) : n - done;
    ssize_t w = write(fd, chunk, want);

    if (w < 0)
      die("repeated write");
    done += (size_t)w;
  }
  close(fd);
}

/* Runs `path` and reports how it terminated via *killed_by_sigkill /
 * *exited_cleanly. Blocks until it exits. `arg1`, if non-NULL, is
 * passed as argv[1] (used to re-exec /init itself with
 * --clean-marker). */
static void run_and_wait(const char *path, const char *arg1,
                         int *killed_by_sigkill, int *exited_cleanly,
                         int *exit_code) {
  pid_t pid = fork();
  int status;

  if (pid < 0)
    die("fork");

  if (pid == 0) {
    char *const argv[] = {(char *)path, (char *)arg1, NULL};

    /* Touch `path`'s first byte before exec, forcing its page
     * resident via a normal (sleepable) userspace fault. Without
     * this, a freshly-started static binary whose .rodata page
     * holding this exact string has never been referenced can hit a
     * real, narrow gap in av.ko's kprobe hook: strncpy_from_user()
     * in handler_pre() runs in atomic/kprobe context and CANNOT
     * sleep to fault in a not-yet-resident page - it fails fast with
     * -EFAULT instead, so the hook silently skips the exec (returns
     * 0 without hashing/killing). The kernel's OWN later, in-process
     * getname_flags() call on the exact same pointer runs in normal
     * sleepable context and faults the page in fine, which is why
     * execve() itself still proceeds normally afterward - it's only
     * the kprobe's earlier, atomic-context copy that loses the race.
     * A real shell invoking a real file essentially never hits this:
     * by the time a shell calls execve(), its own memory (including
     * wherever the pathname string lives) has had far too much prior
     * activity for anything to still be a cold page. It took a
     * minimal, just-booted static init calling execve() on its own
     * literal string within milliseconds of process start to
     * actually observe it - see av/main.c's handler_pre() comment for
     * the same note on the production side. Confirmed via kprobe-side
     * debug tracing that removing this touch reproduces the EFAULT
     * and re-adding it fixes it, consistently, regardless of kernel
     * config (tinyconfig/defconfig), KVM vs TCG, or SMAP/SMEP.
     *
     * This touch is what makes THIS check specifically exercise the
     * common/intended case (detection working, given a realistic
     * pathname) rather than the edge case - it is deliberately NOT
     * applied to cold_launcher.c's own internal exec, which exists
     * specifically to reproduce the untouched-page case instead of
     * avoiding it (see main()'s cold-pathname regression block, and
     * cold_launcher.c's own header comment). */
    {
      volatile char touch = path[0];
      (void)touch;
    }

    execv(path, argv);
    /* Only reached if execv itself failed (e.g. ENOEXEC for a
     * non-ELF/non-script file like eicar.com). The kill for a
     * malicious file is workqueue-deferred (async), so it can in
     * principle race against this process's own synchronous
     * failure-and-exit path. 1 second, not a token 100ms: matches
     * tests/test_detection.sh's own `sleep 1` for the identical
     * async-kill-vs-local-exit race on real hardware - no reason this
     * environment's workqueue would be reliably faster. */
    usleep(1000000);
    _exit(127);
  }

  if (waitpid(pid, &status, 0) < 0)
    die("waitpid");

  *killed_by_sigkill = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
  *exited_cleanly = WIFEXITED(status);
  *exit_code = *exited_cleanly ? WEXITSTATUS(status) : -1;
}

/* Reads the full kernel log ring buffer via the same syslog(2)
 * mechanism `dmesg` uses - no /dev/kmsg or dmesg binary needed. */
static char *read_kernel_log(void) {
  static char buf[65536];
  int n = syscall(SYS_syslog, /* SYSLOG_ACTION_READ_ALL */ 3, buf,
                  sizeof(buf) - 1);
  if (n < 0)
    die("syslog(SYSLOG_ACTION_READ_ALL)");
  buf[n] = '\0';
  return buf;
}

/* ---- #48: helpers for the fanotify exec gate integration case ---- */

/* Both gate cases below are deliberately NON-ELF files, and that is
 * the whole trick that makes this attributable to avd.
 *
 * execve() on a non-ELF file can never succeed, so the question is
 * never "did it run" - it is only WHICH error it failed with:
 *
 *   ENOEXEC - the exec was allowed through and the kernel's binfmt
 *             layer then rejected the file as not an executable
 *             format. This is the ungated outcome.
 *   EPERM   - FAN_OPEN_EXEC_PERM was answered FAN_DENY. open_exec()
 *             refuses before binfmt is ever consulted.
 *
 * The clean file and the malicious file are the same shape, on the
 * same mount, exec'd by the same call. The only variable between them
 * is the bytes avd scanned, so a difference in errno can only have
 * come from avd's verdict. That is a tighter control than asserting a
 * kill, which av.ko's own netlink path could also produce.
 *
 * `*killed` is reported separately rather than folded into the errno,
 * because av.ko's kprobe path sees these execs too and its kill is
 * workqueue-deferred: a SIGKILL landing here means the netlink path
 * got there first, which is a different (and still interesting)
 * outcome from the gate's synchronous refusal - not something to
 * quietly average together. */
static void exec_expect_failure(const char *path, int *exec_errno,
                                int *killed) {
  pid_t pid = fork();
  int status;

  if (pid < 0)
    die("fork");

  if (pid == 0) {
    char *const argv[] = {(char *)path, NULL};

    /* Same cold-pathname touch run_and_wait() explains at length -
     * this case is about avd's gate, not about reproducing av.ko's
     * kprobe EFAULT gap, so the pathname page is faulted in first to
     * keep that variable out of the result. */
    {
      volatile char touch = path[0];
      (void)touch;
    }

    execv(path, argv);

    /* Deliberately NO usleep() before _exit(), unlike run_and_wait():
     * there the sleep gives the deferred kill time to land, because a
     * kill is what that check wants to observe. Here the errno IS the
     * observation, so this exits immediately to carry it back before
     * av.ko's workqueue can turn the result into a SIGKILL and
     * destroy it. */
    _exit(errno);
  }

  if (waitpid(pid, &status, 0) < 0)
    die("waitpid");

  *killed = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
  *exec_errno = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* waitpid() with a deadline, so a daemon that does not shut down is a
 * reported failure rather than a hung job that reads as infrastructure
 * flake. Returns 1 if it exited on its own, 0 if it had to be
 * SIGKILLed.
 *
 * *term_sig reports how it died, and is separate from *exit_code on
 * purpose: a daemon that segfaults on the way out is reaped exactly
 * like one that returned 0, so a caller reading only the return value
 * would call a crash a clean shutdown. Collapsing both into a single
 * -1 would still not distinguish "crashed" from "exited 1", and this
 * is a test whose diagnostic is the whole product. */
static int wait_for_exit(pid_t pid, int timeout_ms, int *exit_code,
                         int *term_sig) {
  int waited = 0;
  int status;

  for (;;) {
    pid_t r = waitpid(pid, &status, WNOHANG);

    if (r == pid) {
      *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      *term_sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
      return 1;
    }
    if (r < 0)
      die("waitpid(daemon)");
    if (waited >= timeout_ms)
      break;
    {
      struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000L};
      nanosleep(&ts, NULL);
    }
    waited += 50;
  }

  kill(pid, SIGKILL);
  waitpid(pid, &status, 0);
  *exit_code = -1;
  *term_sig = SIGKILL;
  return 0;
}

/* Drains whatever avd left on the pipe. Every caller must have reaped
 * avd first, and that ordering is load-bearing: avd never calls
 * setvbuf() or fflush(), so its stdout is fully buffered the moment it
 * is a pipe rather than a tty, and the lines this asserts on do not
 * leave its buffer until exit flushes them. Reading earlier would see
 * nothing and prove nothing.
 *
 * This is also why readiness below is polled by behaviour instead of
 * by watching for the "gate active" line: that line is sitting in
 * avd's buffer for as long as it would be useful.
 *
 * The poll() timeout is not how that ordering is enforced - stop_avd()
 * is - but it bounds the damage if some future branch forgets. This
 * pipe has no O_NONBLOCK and init closes its own write end at fork, so
 * EOF requires avd to be gone; draining while it still lives used to
 * block here forever, and since the branches that print avd's stdout
 * are the ones diagnosing a broken gate, a real regression surfaced as
 * a hung job killed by the workflow's outer timeout rather than as the
 * FAIL it should be. A truncated diagnostic is a bad result; an
 * inconclusive run is a worse one. */
#define DRAIN_TIMEOUT_MS 5000

static char *drain_pipe(int fd) {
  static char buf[32768];
  size_t used = 0;

  for (;;) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
    int pret = poll(&pfd, 1, DRAIN_TIMEOUT_MS);
    ssize_t n;

    if (pret < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (pret == 0) {
      outmsg("QEMU_TEST: WARN: drain_pipe() timed out with avd's write "
             "end still open - it was not reaped before draining; the "
             "output below may be short\n");
      break;
    }

    n = read(fd, buf + used, sizeof(buf) - 1 - used);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (n == 0)
      break;
    used += (size_t)n;
    if (used >= sizeof(buf) - 1)
      break;
  }
  buf[used] = '\0';
  return buf;
}

/* SIGTERM, then reap - SIGKILLing after 15s if it comes to that.
 * Needed before draining on any branch that bails out with avd still
 * running: EOF on the pipe requires avd's write end to close, and
 * SIGTERM rather than SIGKILL because exit() is what flushes the
 * buffered stdout these branches are trying to print. */
static void stop_avd(pid_t pid) {
  int code, sig;

  if (kill(pid, SIGTERM) != 0)
    die("kill(avd, SIGTERM)");
  (void)wait_for_exit(pid, 15000, &code, &sig);
}

int main(int argc, char *const argv[]) {
  if (argc > 1 && !strcmp(argv[1], "--clean-marker")) {
    _exit(42);
  }

  /* ---- pid 1 setup ---- */
  if (mount("proc", "/proc", "proc", 0, NULL) != 0)
    die("mount /proc");
  /* CONFIG_DEVTMPFS_MOUNT already auto-mounts /dev before init runs -
   * EBUSY here just means that already happened, not a real failure. */
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0 && errno != EBUSY)
    die("mount /dev");
  if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) != 0)
    die("mount /tmp");

  outmsg("QEMU_TEST: init started\n");

  /* ---- load av.ko (init_module(2) directly - no insmod binary) ---- */
  {
    int fd = open("/av.ko", O_RDONLY);
    struct stat st;
    void *image;

    if (fd < 0)
      die("open /av.ko");
    if (fstat(fd, &st) != 0)
      die("fstat /av.ko");
    /* st_size is attacker-influenced only in the sense that /av.ko comes
     * from the test initramfs we built ourselves, but validating it here
     * costs nothing and keeps a truncated/corrupt image from turning into
     * a huge malloc or a short read passed to init_module as if whole. */
    if (!S_ISREG(st.st_mode))
      die("/av.ko not a regular file");
    if (st.st_size <= 0 || st.st_size > (off_t)(32 * 1024 * 1024))
      die("/av.ko size out of bounds");
    image = malloc((size_t)st.st_size);
    if (!image)
      die("malloc for module image");
    {
      size_t remaining = (size_t)st.st_size;
      char *p = image;
      while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0)
          die("read /av.ko");
        if (n == 0)
          die("read /av.ko: short read");
        p += n;
        remaining -= (size_t)n;
      }
    }
    close(fd);

    if (syscall(SYS_init_module, image, (unsigned long)st.st_size, "") != 0)
      die("init_module(av.ko)");
    free(image);
  }
  outmsg("QEMU_TEST: av.ko loaded\n");

  /* ---- clean-file check: exec ourselves with --clean-marker, must
   * exit(42) normally, not be killed ---- */
  {
    int killed, exited, code;
    run_and_wait("/init", "--clean-marker", &killed, &exited, &code);
    if (killed) {
      outmsg("QEMU_TEST: FAIL: clean-marker exec was killed (false "
             "positive)\n");
      poweroff_now();
      return 1;
    }
    if (!exited || code != 42) {
      outmsg("QEMU_TEST: FAIL: clean-marker exec exited unexpectedly "
             "(exited=%d code=%d)\n",
             exited, code);
      poweroff_now();
      return 1;
    }
  }
  outmsg("QEMU_TEST: clean-file check passed\n");

  /* ---- EICAR check: must be killed with SIGKILL, and dmesg must
   * show the structured detection line ---- */
  {
    int killed, exited, code;

    write_file("/tmp/eicar.com", EICAR);
    run_and_wait("/tmp/eicar.com", NULL, &killed, &exited, &code);

    if (!killed) {
      outmsg("QEMU_TEST: FAIL: EICAR exec was NOT killed by SIGKILL "
             "(exited=%d code=%d)\n",
             exited, code);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    {
      char *log = read_kernel_log();
      if (!strstr(log, "event=detected") || !strstr(log, "action=kill") ||
          !strstr(log, "type=signature") ||
          !strstr(log, "path=\"/tmp/eicar.com\"")) {
        outmsg("QEMU_TEST: FAIL: EICAR was killed but dmesg is missing the "
               "expected structured detection line\n");
        outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", log);
        poweroff_now();
        return 1;
      }
    }
  }
  outmsg("QEMU_TEST: EICAR detection check passed\n");

  /* ---- Regression case: cold-pathname exec ----
   * av/main.c's handler_pre() comment is the authoritative writeup of
   * the gap this is aimed at. cold_launcher.c is a dedicated, separate
   * binary specifically so its embedded pathname literal has the best
   * chance of being genuinely untouched at exec time - see its own
   * header comment for why init.c can't offer that itself, and
   * AV_EXPECT_COLD_EXEC_DETECTED above for what actually happens.
   *
   * Unlike the EICAR check above, nothing here touches the pathname
   * before exec; that touch is what makes the primary check exercise
   * the common case, and skipping it is the whole point. */
  {
    int killed, exited, code;
    char *log;

    write_file("/tmp/eicar_cold.com", EICAR);
    run_and_wait("/cold_launcher", NULL, &killed, &exited, &code);

    /* Rule out a broken harness before interpreting the outcome either
     * way. Exactly two shapes are meaningful: SIGKILL (av.ko caught the
     * cold exec), or cold_launcher.c's own `return 1` after its inner
     * execve() fails ENOEXEC (it survived). Anything else - notably
     * code 127, run_and_wait's OWN outer execv() failing because
     * /cold_launcher is missing or non-executable in the initramfs -
     * says nothing about av/main.c. */
    if (!killed && !(exited && code == 1)) {
      outmsg("QEMU_TEST: FAIL: cold-pathname case is broken - "
             "/cold_launcher exited unexpectedly (exited=%d code=%d, not "
             "killed). Expected either a SIGKILL or its own exit code 1; "
             "code 127 means /cold_launcher is missing or non-executable "
             "in the initramfs. This is a defect in this harness, not in "
             "the av/main.c gap it is aimed at.\n",
             exited, code);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    /* Corroborate the exit status against dmesg rather than trusting
     * it alone - a SIGKILL from anything other than av.ko would
     * otherwise read as a successful detection. This substring is
     * contiguous in av_kill()'s format string and names the inner
     * exec specifically, so the EICAR check's own kill line above
     * cannot satisfy it. */
    log = read_kernel_log();
    {
      const int detected =
          strstr(log, "action=kill type=signature "
                      "path=\"/tmp/eicar_cold.com\"") != NULL;

      if (AV_EXPECT_COLD_EXEC_DETECTED) {
        if (!killed || !detected) {
          outmsg("QEMU_TEST: FAIL: cold exec was NOT detected "
                 "(killed=%d dmesg-kill-line=%d exited=%d code=%d). "
                 "AV_EXPECT_COLD_EXEC_DETECTED says this harness detects "
                 "it - every kernel in the matrix did when that was set. "
                 "So either exec-time detection regressed, or this "
                 "harness has started genuinely reproducing the "
                 "cold-page bypass of issue #2. Establish which before "
                 "touching this check; if it is the latter, that is a "
                 "real finding for #2 and discussion #33, not something "
                 "to silence by flipping the toggle.\n",
                 killed, detected, exited, code);
          outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", log);
          poweroff_now();
          return 1;
        }
        outmsg("QEMU_TEST: cold exec detected and killed - note this "
               "harness does not reproduce the issue #2 bypass, so this "
               "is a detection regression guard, not evidence about "
               "that gap\n");
      } else {
        if (killed || detected) {
          outmsg("QEMU_TEST: FAIL: cold exec WAS detected "
                 "(killed=%d dmesg-kill-line=%d), but "
                 "AV_EXPECT_COLD_EXEC_DETECTED says this harness "
                 "reproduces the bypass. Good news if the harness was "
                 "just made to reproduce it and detection then caught "
                 "up - flip the toggle back to 1 and update issue #2 "
                 "and SECURITY.md to match.\n",
                 killed, detected);
          outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", log);
          poweroff_now();
          return 1;
        }
        outmsg("QEMU_TEST: cold-pathname bypass reproduced as documented "
               "(exited=%d code=%d, not killed, no kill line in dmesg)\n",
               exited, code);
      }
    }
  }

  /* ---- #48: the fanotify exec gate, end to end through avd itself ----
   *
   * tests/test_fanotify_exec_gate.sh already covers this in two halves
   * that never meet: static greps pinning the integration's shape, and
   * tests/fanotify_exec_gate.c driving the raw fanotify mechanism with
   * avd's own flags but a hardcoded content check standing in for the
   * verdict. Neither half ever starts avd, so the seam between them -
   * a real avd, marking a real mount, answering FAN_OPEN_EXEC_PERM
   * with a verdict that actually came out of perform_scan() - was
   * unproven until here. That is the whole reason this case exists in
   * the one job that has a real kernel with av.ko loaded.
   *
   * The signal it reads is an errno, not a kill: both samples are
   * non-ELF, so execve() can never succeed on either and the only
   * variable left is WHICH failure comes back. FAN_OPEN_EXEC_PERM is
   * answered inside open_exec(), before any binfmt handler is
   * consulted, so a denied exec fails EPERM while an allowed one runs
   * on and fails ENOEXEC at binfmt_elf. Verified directly against a
   * live kernel rather than assumed: a standalone FAN_CLASS_CONTENT
   * mark on a tmpfs answering FAN_ALLOW then FAN_DENY for the same
   * non-ELF file gave errno 8 (ENOEXEC) and errno 1 (EPERM)
   * respectively. Reading an errno is tighter than asserting a kill,
   * because av.ko's netlink path can produce a kill too and that
   * would not be attributable to the gate.
   *
   * It runs LAST on purpose. It is the only case in this file that
   * leaves a daemon running, and marking /tmp gates every exec on that
   * mount for as long as avd lives - so anything added after this must
   * account for both. */
  if (access("/avd", X_OK) != 0) {
    /* Two harnesses boot this init: the CI job, which stages avd and
     * its whole ldd closure, rules and corpus into the initramfs, and
     * tests/test_detection_qemu.sh, which stages only init,
     * cold_launcher and av.ko because it exists to exercise the
     * kernel module and deliberately carries none of avd's build
     * dependencies. Skipping here rather than failing keeps the local
     * harness meaningful instead of red for a reason that has nothing
     * to do with what it tests.
     *
     * A skip is only safe because it cannot happen unnoticed where it
     * matters: the CI job greps the serial log for this case's PASS
     * marker and fails the build if it is absent, so a silently
     * skipped gate case there is already an error. */
    outmsg("QEMU_TEST: SKIP: /avd not staged in this initramfs - the "
           "fanotify exec gate case needs the daemon (CI stages it; the "
           "local av.ko harness does not)\n");
  } else {
    const char *malicious = "/tmp/gate_malicious";
    const char *clean = "/tmp/gate_clean";
    /* Matches tests/fixtures/test.yar's
     * Suspicious_Shell_Reverse_Shell_String (weight=100, override=true),
     * which that file's own header explains is a test fixture that must
     * never reach a production rules dir.
     *
     * Deliberately NOT the EICAR string the checks above use: EICAR's
     * SHA-256 is in av.ko's own signature table, so an EICAR file would
     * be convicted by the kernel's netlink path as well, and a denied
     * exec could no longer be attributed to the gate. This content is
     * invisible to av.ko and convicted only by avd's YARA pass.
     *
     * No `#!` on either file, and that matters: a shebang would make
     * binfmt_script the thing that handles the exec, and it would fail
     * with ENOENT looking for an interpreter that does not exist in
     * this initramfs. Without one, a non-ELF file reaches binfmt_elf
     * and fails ENOEXEC, which is the ungated outcome this case reads
     * as its baseline. */
    const char *malicious_content = "/bin/sh -i\n";
    /* Measured, not assumed: the clean sample is not rule-free, it is
     * under-threshold. Any non-ELF file trivially satisfies
     * elf_analysis.yar's Entry_Point_Outside_Text (there is no .text
     * section for an entry point to fall inside), so BOTH samples here
     * carry its weight of 30. Conviction is
     * `override_matched || score >= MALICIOUS_SCORE_THRESHOLD` (100),
     * so 30 is CLEAN with room to spare, and what separates the two
     * files is the fixture rule's override, not the score. If a future
     * rule starts matching plain text, this case is what notices -
     * and padding this file's content is the wrong fix. */
    const char *clean_content = "nothing in this file is interesting\n";
    const int deadline_ms = 60000;
    int err, killed, code, sig;
    int last_err = -1, last_killed = 0;
    int waited = 0, denied = 0;
    pid_t avd_pid;
    int pipefd[2];
    char *avd_out;
    struct stat st;

    write_file(malicious, malicious_content);
    write_file(clean, clean_content);

    /* Baseline, before avd exists. This is the vacuity guard for
     * everything below: it establishes that ENOEXEC is what an
     * ungated exec of these files looks like on this mount, so the
     * EPERM asserted later cannot be something ambient that was
     * always true. Both files, because the two must be
     * indistinguishable until avd is the thing telling them apart. */
    exec_expect_failure(malicious, &err, &killed);
    if (killed || err != ENOEXEC) {
      outmsg("QEMU_TEST: FAIL: gate baseline is broken - ungated exec of "
             "%s gave errno=%d killed=%d, expected ENOEXEC (%d). Without "
             "this the EPERM checked below would prove nothing.\n",
             malicious, err, killed, ENOEXEC);
      poweroff_now();
      return 1;
    }
    exec_expect_failure(clean, &err, &killed);
    if (killed || err != ENOEXEC) {
      outmsg("QEMU_TEST: FAIL: gate baseline is broken - ungated exec of "
             "%s gave errno=%d killed=%d, expected ENOEXEC (%d)\n",
             clean, err, killed, ENOEXEC);
      poweroff_now();
      return 1;
    }
    outmsg("QEMU_TEST: gate baseline established (ungated exec = ENOEXEC)\n");

    /* avd walks a path's parents all the way to "/" and refuses any
     * directory an unprivileged uid controls, so a "/" that is not
     * root-owned makes it decline its quarantine dir - and then a
     * conviction denies the exec but leaves the file in place, which
     * looks exactly like a quarantine bug further down. The initramfs
     * is built with `cpio -R root:root` for this reason; check the
     * result here so that if that ever regresses, the failure names
     * the archive instead of blaming perform_scan(). Not repaired
     * with a chown: a guest rootfs owned by the CI runner's uid is
     * wrong for every other check in this file too, and hiding it
     * here would leave the next one to rediscover it. */
    if (stat("/", &st) != 0) {
      outmsg("QEMU_TEST: FAIL: cannot stat / to check its ownership\n");
      poweroff_now();
      return 1;
    }
    if (st.st_uid != 0) {
      outmsg("QEMU_TEST: FAIL: / is owned by uid %d, not root - the "
             "initramfs was packed without `cpio -R root:root`, so avd "
             "will refuse its quarantine dir and this case cannot mean "
             "anything\n",
             (int)st.st_uid);
      poweroff_now();
      return 1;
    }

    /* avd's stdout goes to a pipe, not the console, so the lines it
     * prints can be asserted on rather than merely eyeballed in the
     * serial log. Its stderr is left pointing at the console, where it
     * is unbuffered and shows up live - which is what a failing run
     * needs. See drain_pipe() for why the pipe is only read at the
     * end. */
    if (pipe(pipefd) != 0)
      die("pipe for avd stdout");

    avd_pid = fork();
    if (avd_pid < 0)
      die("fork avd");
    if (avd_pid == 0) {
      char *const av_argv[] = {(char *)"/avd", NULL};

      close(pipefd[0]);
      if (dup2(pipefd[1], 1) < 0)
        _exit(120);
      close(pipefd[1]);

      /* Every path avd needs, named explicitly - none of the compiled-in
       * defaults (/etc/hyprav/...) exist in this initramfs. */
      setenv("AVD_RULES_DIR", "/av-rules", 1);
      setenv("AVD_CORPUS_FILE", "/av-corpus/fuzzy_hashes.txt", 1);
      setenv("AVD_TLSH_CORPUS_FILE", "/av-corpus/tlsh_hashes.txt", 1);
      setenv("AVD_QUARANTINE_DIR", "/tmp/av-quarantine", 1);
      setenv("AVD_SOCK_PATH", "/tmp/avd.sock", 1);
      /* This initramfs has no /etc/ld.so.cache - the workflow copies
       * avd's library closure in at the absolute paths ldd reported
       * and nothing ever runs ldconfig. The loader would then be
       * relying purely on its built-in default search path, which does
       * cover Debian/Ubuntu's multiarch directories but is exactly the
       * kind of implicit dependency that turns into a bare "error
       * while loading shared libraries" with no other clue. Naming the
       * directories outright costs nothing and keeps the failure mode
       * out of the picture. */
      setenv("LD_LIBRARY_PATH",
             "/lib:/usr/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu",
             1);
      /* The gate itself. /tmp is a tmpfs mounted by this init, so the
       * blast radius of marking it is exactly the files staged here -
       * notably NOT the rootfs holding /init and /avd. */
      setenv("AVD_FANOTIFY_EXEC", "1", 1);
      setenv("AVD_FANOTIFY_MARK", "/tmp", 1);

      execv("/avd", av_argv);
      _exit(121);
    }
    close(pipefd[1]);

    /* Readiness is polled by behaviour rather than by watching for
     * avd's "gate active" line, because that line is block-buffered
     * inside avd for as long as it would be useful (drain_pipe() has
     * the detail). Re-staging the file every iteration is not
     * belt-and-braces: a conviction quarantines it, so the file is
     * gone after the first attempt that avd actually scans. */
    while (waited < deadline_ms) {
      pid_t r = waitpid(avd_pid, &code, WNOHANG);

      if (r == avd_pid) {
        outmsg("QEMU_TEST: FAIL: avd exited during startup (status %d) - "
               "the gate never armed. 120/121 mean the exec of /avd "
               "itself failed, which points at a missing shared library "
               "in the initramfs rather than at the gate.\n",
               WIFEXITED(code) ? WEXITSTATUS(code) : -1);
        outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", drain_pipe(pipefd[0]));
        poweroff_now();
        return 1;
      }

      write_file(malicious, malicious_content);
      exec_expect_failure(malicious, &err, &killed);
      last_err = err;
      last_killed = killed;
      if (!killed && err == EPERM) {
        denied = 1;
        break;
      }
      {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000L};
        nanosleep(&ts, NULL);
      }
      waited += 200;
    }

    if (!denied) {
      outmsg("QEMU_TEST: FAIL: the exec gate never denied %s within %dms "
             "(last errno=%d killed=%d). errno=%d (ENOEXEC) throughout "
             "means avd is running but never marked the mount; killed=1 "
             "means av.ko's netlink path convicted the file first, so "
             "avd and its rules are fine and it is specifically the "
             "fanotify gate that did not engage.\n",
             malicious, deadline_ms, last_err, last_killed, ENOEXEC);
      stop_avd(avd_pid); /* avd is still up here - see drain_pipe() */
      outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", drain_pipe(pipefd[0]));
      poweroff_now();
      return 1;
    }
    outmsg("QEMU_TEST: exec gate DENIED the malicious file (EPERM, "
           "pre-exec)\n");

    /* A gate that denies everything would pass the check above while
     * being useless, so the clean file - same mount, same non-ELF
     * shape, different bytes - has to still reach binfmt. */
    exec_expect_failure(clean, &err, &killed);
    if (killed || err != ENOEXEC) {
      outmsg("QEMU_TEST: FAIL: the exec gate did not allow the clean file "
             "(errno=%d killed=%d, expected ENOEXEC %d) - it is denying "
             "on something other than the verdict\n",
             err, killed, ENOEXEC);
      stop_avd(avd_pid); /* avd is still up here - see drain_pipe() */
      outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", drain_pipe(pipefd[0]));
      poweroff_now();
      return 1;
    }
    outmsg("QEMU_TEST: exec gate ALLOWED the clean file\n");

    /* perform_scan() quarantines what it convicts, on the gate's path
     * as much as on the netlink one, so the denied file must be gone
     * from where it was staged. This corroborates the EPERM against a
     * second, independent effect of the same verdict. */
    if (stat(malicious, &st) == 0) {
      outmsg("QEMU_TEST: FAIL: %s was denied but is still at its original "
             "path - perform_scan() convicted it without quarantining\n",
             malicious);
      poweroff_now();
      return 1;
    }

    /* Shutdown. fanexec_stop() joins the responders before closing the
     * fanotify fd, which is what releases any still-pending permission
     * event; a daemon that cannot complete that leaves execs suspended
     * on the marked mount with no kernel-side timeout, so "it exited"
     * is a real assertion here and not a formality. */
    if (kill(avd_pid, SIGTERM) != 0)
      die("kill(avd, SIGTERM)");
    if (!wait_for_exit(avd_pid, 15000, &code, &sig)) {
      outmsg("QEMU_TEST: FAIL: avd did not exit within 15s of SIGTERM and "
             "had to be SIGKILLed - the gate's shutdown path is stuck, "
             "which is the state that strands suspended execs\n");
      /* Expect this to be empty, and do not read that as a broken
       * drain: avd never flushes, so a SIGKILLed avd takes its whole
       * block-buffered stdout with it. Its stderr is on the console
       * above, which is where a stuck shutdown actually shows itself. */
      outmsg("QEMU_TEST: --- avd stdout (empty if SIGKILLed - see "
             "stderr on the console above) ---\n%s\n",
             drain_pipe(pipefd[0]));
      poweroff_now();
      return 1;
    }

    /* Reaped is not the same as shut down cleanly. avd returns 1 from
     * main() when startup failed or when fanexec_abort() fired - an
     * unrecoverable gate failure that SIGTERMs the process itself - so
     * a gate that collapsed and tore itself down would be reaped here
     * exactly like a healthy one, and without this the case would go
     * on to report a clean shutdown. A signal means it crashed on the
     * way out instead, which is the same story with a worse ending:
     * either way the responders never joined and the mark's release is
     * the kernel's doing rather than avd's. */
    if (sig != 0 || code != 0) {
      if (sig != 0)
        outmsg("QEMU_TEST: FAIL: avd was killed by signal %d during "
               "shutdown rather than exiting - the teardown path "
               "crashed\n",
               sig);
      else
        outmsg("QEMU_TEST: FAIL: avd exited %d on SIGTERM, not 0 - main() "
               "returns 1 for a failed startup or a fanexec_abort(), so "
               "the gate did not simply stop, it gave up\n",
               code);
      outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", drain_pipe(pipefd[0]));
      poweroff_now();
      return 1;
    }

    /* The mount must be usable again once the gate is gone. This is
     * the observable half of "no exec was left suspended": if the
     * fanotify group had not been torn down cleanly, this exec would
     * hang here rather than fail fast. */
    write_file(malicious, malicious_content);
    exec_expect_failure(malicious, &err, &killed);
    if (err != ENOEXEC) {
      outmsg("QEMU_TEST: FAIL: after avd exited, exec of %s gave errno=%d "
             "killed=%d - expected ENOEXEC (%d), i.e. the mark released "
             "and the mount back to its ungated behaviour\n",
             malicious, err, killed, ENOEXEC);
      poweroff_now();
      return 1;
    }

    /* Only now is the pipe worth reading: avd has exited, so its
     * buffered stdout has been flushed and the write end is closed.
     * The exit-code and errno checks above say the right things
     * happened; these two lines say avd is the thing that did them. */
    avd_out = drain_pipe(pipefd[0]);
    close(pipefd[0]);
    if (!strstr(avd_out, "fanotify exec gate active")) {
      outmsg("QEMU_TEST: FAIL: avd never reported the exec gate active, "
             "yet the checks above passed - something other than the "
             "gate is producing these results\n");
      outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", avd_out);
      poweroff_now();
      return 1;
    }
    if (!strstr(avd_out, "fanotify exec DENIED") ||
        !strstr(avd_out, "path=\"/tmp/gate_malicious\"")) {
      outmsg("QEMU_TEST: FAIL: the exec was refused with EPERM but avd "
             "logged no matching fanotify denial - the refusal did not "
             "come from the gate\n");
      outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", avd_out);
      poweroff_now();
      return 1;
    }
    outmsg("QEMU_TEST: avd shut down cleanly and released the mark\n");
    /* Inside the else, never after it. The CI job greps for exactly
     * this line to prove the case was not quietly dropped, so printing
     * it on the skip path would forge the evidence that guard exists
     * to check. */
    outmsg("QEMU_TEST: fanotify exec gate integration check passed\n");
    /* ---- #51: AVD_FANOTIFY_FAIL_CLOSED at runtime, via the
     * incomplete-scan path ----
     *
     * The case above proves the gate's verdict path (malicious DENY,
     * clean ALLOW) but starts avd without the flag, so every
     * no-verdict path takes its default FAN_ALLOW and the fail-closed
     * contract is never observed. This starts a SECOND avd with
     * AVD_FANOTIFY_FAIL_CLOSED=1 and AVD_SCAN_TIMEOUT_SECS=1, then
     * execs a file whose scan cannot conclude in that budget: 8KB of
     * identical bytes against tests/fixtures/fail_closed_slow.yar's
     * calibration rule, whose nested quantifier needs ~6s on libyara
     * 4.5.x while matching nothing (no 'b' present, so no conviction
     * regardless of score - and weight=1 could never convict alone
     * anyway). perform_scan() reports CLEAN with incomplete=1, and
     * the handler must deny it because the flag is set.
     *
     * Same errno discipline as the verdict case: both samples are
     * non-ELF, so the only variable is ENOEXEC (allowed through to
     * binfmt) vs EPERM (the gate denied pre-exec). Attribution comes
     * from the same two controls: the first avd's clean file staying
     * ENOEXEC, and avd's own stdout naming the deny reason. The
     * distinguishing assertion is the log line: "did not complete",
     * not "DENIED ... rule=", proving the denial came from the
     * incomplete branch rather than a detection.
     *
     * Non-vacuity is two-sided, per #45: the slow file must be
     * ALLOWED (ENOEXEC) under a fail-open avd with the same 1s
     * budget - proving the file is scannable-but-slow rather than
     * unloadable - and the flag-less first avd above already showed
     * clean content reaching binfmt. If the incomplete branch ever
     * stops consulting the flag, this fails: EPERM where ENOEXEC is
     * asserted, or vice versa. */
    {
      const char *slow = "/tmp/gate_slow";
      const char *slow_clean = "/tmp/gate_slow_clean";
      pid_t fc_pid;
      int fc_pipe[2];
      char *fc_out;
      int fc_waited = 0, fc_denied = 0;
      int fc_err = -1, fc_killed = 0;

      write_repeated(slow, 'a', 8192);
      write_file(slow_clean, clean_content);

      if (pipe(fc_pipe) != 0)
        die("pipe for fail-closed avd stdout");
      fc_pid = fork();
      if (fc_pid < 0)
        die("fork fail-closed avd");
      if (fc_pid == 0) {
        char *const av_argv[] = {(char *)"/avd", NULL};

        close(fc_pipe[0]);
        if (dup2(fc_pipe[1], 1) < 0)
          _exit(120);
        close(fc_pipe[1]);
        setenv("AVD_RULES_DIR", "/av-rules", 1);
        setenv("AVD_CORPUS_FILE", "/av-corpus/fuzzy_hashes.txt", 1);
        setenv("AVD_TLSH_CORPUS_FILE", "/av-corpus/tlsh_hashes.txt", 1);
        setenv("AVD_QUARANTINE_DIR", "/tmp/av-quarantine", 1);
        /* Separate socket path: the control socket is a filesystem
         * path, and the first avd is gone by now - but reusing its
         * path would turn a shutdown-ordering bug into a bind
         * failure here, blaming this case for the earlier one's
         * teardown. */
        setenv("AVD_SOCK_PATH", "/tmp/avd-fc.sock", 1);
        setenv("LD_LIBRARY_PATH",
               "/lib:/usr/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu",
               1);
        setenv("AVD_FANOTIFY_EXEC", "1", 1);
        setenv("AVD_FANOTIFY_MARK", "/tmp", 1);
        setenv("AVD_FANOTIFY_FAIL_CLOSED", "1", 1);
        /* 1s budget: the slow file needs ~6s, small files need ~1ms
         * (calibrated on libyara 4.5.8 - see the fixture's header).
         * TCG only widens the margin. */
        setenv("AVD_SCAN_TIMEOUT_SECS", "1", 1);
        execv("/avd", av_argv);
        _exit(121);
      }
      close(fc_pipe[1]);

      /* Readiness, same behaviour-poll shape as the verdict case:
       * re-stage the slow file every iteration (a fail-open avd
       * would allow it; nothing quarantines a CLEAN file either
       * way, but a stale path would forge ENOENT into evidence),
       * and treat the first EPERM as armed. Deadline is generous:
       * avd startup (rule compile) plus the 1s scan itself, all
       * under TCG. */
      while (fc_waited < deadline_ms) {
        pid_t r = waitpid(fc_pid, &code, WNOHANG);

        if (r == fc_pid) {
          outmsg("QEMU_TEST: FAIL: fail-closed avd exited during startup "
                 "(status %d) - the gate never armed\n",
                 WIFEXITED(code) ? WEXITSTATUS(code) : -1);
          outmsg("QEMU_TEST: --- avd stdout ---\n%s\n",
                 drain_pipe(fc_pipe[0]));
          poweroff_now();
          return 1;
        }
        write_repeated(slow, 'a', 8192);
        exec_expect_failure(slow, &err, &killed);
        last_err = err;
        last_killed = killed;
        if (!killed && err == EPERM) {
          fc_denied = 1;
          break;
        }
        {
          struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000L};
          nanosleep(&ts, NULL);
        }
        fc_waited += 200;
      }
      if (!fc_denied) {
        outmsg("QEMU_TEST: FAIL: fail-closed gate never denied %s within "
               "%dms (last errno=%d killed=%d) - the incomplete-scan "
               "branch is not denying\n",
               slow, deadline_ms, last_err, last_killed);
        stop_avd(fc_pid);
        outmsg("QEMU_TEST: --- avd stdout ---\n%s\n",
               drain_pipe(fc_pipe[0]));
        poweroff_now();
        return 1;
      }
      outmsg("QEMU_TEST: fail-closed gate DENIED the incomplete scan "
             "(EPERM, pre-exec)\n");

      /* Companion control: a small clean file under the SAME 1s budget
       * must still reach binfmt. This proves the EPERM above came
       * from the scan not concluding, not from the 1s budget denying
       * everything or the flag denying unconditionally. */
      exec_expect_failure(slow_clean, &fc_err, &fc_killed);
      if (fc_killed || fc_err != ENOEXEC) {
        outmsg("QEMU_TEST: FAIL: fail-closed gate did not allow the small "
               "clean file under the same 1s budget (errno=%d killed=%d, "
               "expected ENOEXEC %d) - it is denying on something other "
               "than incompleteness\n",
               fc_err, fc_killed, ENOEXEC);
        stop_avd(fc_pid);
        outmsg("QEMU_TEST: --- avd stdout ---\n%s\n",
               drain_pipe(fc_pipe[0]));
        poweroff_now();
        return 1;
      }
      outmsg("QEMU_TEST: fail-closed gate ALLOWED the small clean file "
             "under the same budget\n");

      if (kill(fc_pid, SIGTERM) != 0)
        die("kill(fail-closed avd, SIGTERM)");
      if (!wait_for_exit(fc_pid, 15000, &code, &sig)) {
        outmsg("QEMU_TEST: FAIL: fail-closed avd did not exit within 15s "
               "of SIGTERM and had to be SIGKILLed\n");
        outmsg("QEMU_TEST: --- avd stdout ---\n%s\n",
               drain_pipe(fc_pipe[0]));
        poweroff_now();
        return 1;
      }
      if (sig != 0 || code != 0) {
        if (sig != 0)
          outmsg("QEMU_TEST: FAIL: fail-closed avd was killed by signal "
                 "%d during shutdown rather than exiting\n",
                 sig);
        else
          outmsg("QEMU_TEST: FAIL: fail-closed avd exited %d on SIGTERM, "
                 "not 0 - the gate gave up\n",
                 code);
        outmsg("QEMU_TEST: --- avd stdout ---\n%s\n",
               drain_pipe(fc_pipe[0]));
        poweroff_now();
        return 1;
      }

      /* Attribution, same as the verdict case: exit codes and errnos
       * say the right things happened; avd's own log says it did
       * them, and specifically through the incomplete branch. */
      fc_out = drain_pipe(fc_pipe[0]);
      close(fc_pipe[0]);
      if (!strstr(fc_out, "fanotify exec gate active") ||
          !strstr(fc_out, "fail-closed")) {
        outmsg("QEMU_TEST: FAIL: fail-closed avd never reported the gate "
               "active in fail-closed mode, yet the checks above passed "
               "- something other than the gate is producing these "
               "results\n");
        outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", fc_out);
        poweroff_now();
        return 1;
      }
      if (!strstr(fc_out, "did not complete")) {
        outmsg("QEMU_TEST: FAIL: the slow exec was refused with EPERM but "
               "avd logged no incomplete-scan line - the refusal did not "
               "come from the fail-closed branch\n");
        outmsg("QEMU_TEST: --- avd stdout ---\n%s\n", fc_out);
        poweroff_now();
        return 1;
      }
      outmsg("QEMU_TEST: fail-closed avd shut down cleanly and released "
             "the mark\n");
      outmsg("QEMU_TEST: fanotify fail-closed incomplete-scan check passed\n");
    }
  }

  pass_and_poweroff();
  return 0; /* unreached */
}
