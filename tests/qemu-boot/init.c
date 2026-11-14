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
 * binary this one execs partway through, which drives an exec from a
 * pathname page it guarantees is cold. That used to be a reproducer
 * for a real gap in av.ko's kprobe hook (atomic-context
 * strncpy_from_user() cannot fault in a non-resident page); since the
 * exec hook moved onto the kernel's own exec path (issues #2/#94) the
 * pathname is never read from userspace at all, so it is now a
 * regression guard that requires a detection - see its own header
 * comment, and av/main.c's handler_pre_bprm_check().
 *
 * All output goes through outmsg() (vsnprintf into a buffer + a raw
 * write(2) to fd 1) rather than stdio - printf()+fflush() was tried
 * first and its output never reached the serial console (kernel
 * printk output appeared fine; only userspace stdio output was
 * lost), for reasons not fully root-caused. write() sidesteps
 * whatever that was rather than chasing it further.
 *
 * Runs in one of three modes:
 *   - argv[1] == "--clean-marker": immediately exit(42). This is what
 *     gets exec'd as the "definitely not malicious" test case - no
 *     separate coreutils/busybox binary needed, we just re-exec
 *     ourselves.
 *   - argv[1] == "--self-unlink" / "--self-unlink-early" /
 *     "--self-rename" / "--self-move-unlink" / "--self-badexec-unlink":
 *     the child half of the self-delete cases, run from a copy of this
 *     binary - delete or replace a name, then linger (exit 43 if still
 *     alive). See the comments on each in main().
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

/* The cold-pathname case near the end of main() and the exec-time
 * TOCTOU batch after it target what were issue #2's two halves. Both
 * are now closed, so both assert unconditionally.
 *
 * What changed (issue #94): av.ko's exec hook no longer probes
 * __arm64_sys_execve[at] and copies the pathname argument out of
 * userspace. It probes a function on the kernel's own exec path
 * instead - bprm_execve(), or security_bprm_check() on a kernel where
 * that one is probeable; av.ko logs which at insmod - reached once the
 * target is already open, and pins bprm->file, the exact struct file
 * the kernel is about to execute. That removes both halves at once:
 *
 *   - Cold pages: nothing on the exec path reads userspace memory any
 *     more, so a non-resident pathname page cannot make the hook
 *     fail-open. cold_launcher.c still guarantees a cold page
 *     (file-backed mmap, MADV_DONTNEED'd right before execve - see
 *     its header comment); the exec it drives must be detected and
 *     killed anyway. If it is not, exec-time detection regressed.
 *
 *   - Exec-time TOCTOU (issue #45): the hash comes from the pinned
 *     bprm->file, not from a separate later open of the pathname, so
 *     renaming a decoy over the path after exec cannot change what
 *     gets hashed. Every swap attempt must be detected+killed on the
 *     EICAR that actually executed, and no attempt may produce a
 *     verdict line carrying the decoy's digest.
 *
 * Neither case asserts anything about exec-time BLOCKING: av.ko is
 * still kill-after-exec, because a kprobe pre-handler cannot change
 * the probed function's return value. Prevention is avd's fanotify
 * FAN_OPEN_EXEC_PERM gate, which the #48 case at the end of main()
 * covers separately.
 *
 * Both assertions were deliberately toggles
 * (AV_EXPECT_COLD_EXEC_DETECTED / AV_EXPECT_TOCTOU_CLOSED) while the
 * bypasses were open, so this harness asserted what it could actually
 * observe rather than a fix that had not landed. They are removed
 * rather than set to 1: there is no configuration in which a bypass
 * is the expected outcome again, and a toggle with only one valid
 * value is just a place for a real failure to get silenced.
 *
 * Two pieces of the old rationale are kept because they still carry
 * the swap case:
 *
 *   - Why the swap arm is ordered. An earlier version fired the
 *     rename from the parent "concurrent with" the child's execve()
 *     and counted any decoy-hash line as a win. That was unsound (see
 *     #45): with no ordering, on the single-vCPU TCG leg the parent's
 *     rename usually completed BEFORE the child was scheduled to
 *     exec, so the exec itself resolved the decoy - not a TOCTOU at
 *     all, yet byte-identical in the log, which also made a
 *     "closed" assertion unsatisfiable. The sync pipe below pins the
 *     rename strictly after exec entry, and the reported errno
 *     (ENOEXEC - EICAR is not an ELF) is ground truth that the exec
 *     resolved EICAR. That ordering is what makes "every swap is
 *     killed on the EICAR" a clean per-attempt assertion rather than
 *     a probability.
 *
 *   - The no-swap control, which is the vacuity guard (#34/#45):
 *     without it a broken fixture that never stages EICAR would read
 *     identically to a working scanner.
 *
 * One post-fix consequence worth knowing when reading the matches
 * below: the swap's rename() unlinks the dentry of the inode the
 * kprobe pinned, so d_path() of that still-open file renders as
 * "<target> (deleted)". The kill line for a swap therefore carries
 * either spelling depending on whether the rename beat av_work_fn()'s
 * d_path() call, and both are accepted. (With the delay knob now
 * parking the work item before d_path(), the suffixed form is the one
 * expected; the plain one stays accepted rather than asserting timing
 * this case is not about.) */
#define TOCTOU_SWAP_ATTEMPTS 64

/* sha256 of the exact decoy bytes written below ("toctou decoy - nothing
 * to see here\n"). A fail-open line carrying THIS digest on the exec
 * target's path is unambiguous proof the scanner hashed the decoy and not
 * the EICAR that executed: EICAR would have produced an
 * action=kill/type=signature line instead, and the decoy matches no
 * signature so it can only reach the clean/fail-open branch. Post-#94 no
 * attempt may produce it, which is exactly what the batch asserts; the
 * digest is kept (rather than the assertion reduced to "a kill happened")
 * so a regression is reported as "the scanner hashed the decoy" instead of
 * a bare missing kill. Recompute with
 * `printf 'toctou decoy - nothing to see here\n' | sha256sum` if the
 * decoy bytes ever change. */
#define TOCTOU_DECOY_SHA256                                                   \
  "fd0e0467cee410d82469da45e023e1f6ca372ff1968a5fccc621bd2b6482e4fb"
#define TOCTOU_DECOY_BYTES "toctou decoy - nothing to see here\n"

/* av.ko's test-only knob (av_toctou_test_delay_ms) that parks the
 * deferred work item for this many ms before it d_path()s and hashes, so
 * the swap below is guaranteed to land while the scan is still in flight
 * rather than winning or losing by luck. Pre-#94 this widened the
 * kprobe->open window the bypass lived in; now that the hash reads the
 * pinned bprm->file there is no such window, and the knob's job is the
 * mirror image - make the mid-flight rename certain, so "the digest still
 * came from the executed image" is actually being tested on every
 * attempt. Any value comfortably larger than the parent's
 * post-handshake rename latency (sub-ms even under TCG) works; 150ms
 * leaves a wide margin. The child must outlive the delayed hash so its
 * verdict LINE is emitted against a still-live pid (no reuse), so its
 * linger is the delay plus a generous hash/scheduling margin. */
#define TOCTOU_WQ_DELAY_MS 150
#define TOCTOU_LINGER_US ((TOCTOU_WQ_DELAY_MS + 400) * 1000)
#define TOCTOU_DELAY_PARAM "/sys/module/av/parameters/av_toctou_test_delay_ms"

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

/* Set an integer sysfs/module-param attribute. Unlike write_file() this
 * does NOT pass O_CREAT/O_TRUNC: the target is an existing kernel
 * attribute, and a failure to open it is a real error worth reporting
 * distinctly - most likely av.ko was built without the test-only knob
 * (rebuild the module), or sysfs was not mounted. */
static void write_param_int(const char *path, int val) {
  char buf[16];
  int fd = open(path, O_WRONLY);
  int n;
  if (fd < 0)
    die("open module param (rebuild av.ko with the toctou test knob?)");
  n = snprintf(buf, sizeof(buf), "%d", val);
  if (n < 0 || (size_t)n >= sizeof(buf)) {
    close(fd);
    die("format module param value");
  }
  if (write(fd, buf, (size_t)n) != n) {
    close(fd);
    die("write module param");
  }
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
     * resident via a normal (sleepable) userspace fault. This is now
     * only belt-and-braces: av.ko's exec hook probes the kernel's own
     * exec path and never reads this pointer, so page residency
     * cannot affect detection either way (issue #94).
     *
     * It is kept because of what it used to be load-bearing for, and
     * what that cost to find. While the hook probed
     * __arm64_sys_execve[at] it copied this very pathname out of
     * userspace with strncpy_from_user(), in atomic/kprobe context,
     * where it cannot sleep to fault in a not-yet-resident page: it
     * failed fast with -EFAULT and the hook silently skipped the exec
     * (returned 0 without hashing/killing). The kernel's OWN later,
     * in-process getname_flags() call on the exact same pointer runs
     * sleepable and faults the page in fine, which is why execve()
     * proceeded normally afterward and the skip left no trace. A real
     * shell essentially never hit it - by the time a shell calls
     * execve() its memory has had far too much prior activity for
     * anything to still be cold; it took a minimal, just-booted
     * static init exec'ing its own literal string within milliseconds
     * of process start to observe at all, and kprobe-side debug
     * tracing to confirm that removing this touch reproduced the
     * EFAULT and re-adding it fixed it, consistently, across kernel
     * config (tinyconfig/defconfig), KVM vs TCG, and SMAP/SMEP.
     *
     * Removing it would make this check and cold_launcher.c's exec
     * test the same thing, and would quietly discard the only
     * difference between them if the exec hook ever moves back to a
     * syscall probe. cold_launcher.c deliberately does NOT touch its
     * pathname (see main()'s cold-pathname regression block and that
     * file's header comment), so the two still bracket the question
     * from both sides. */
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

/* ---- helpers for the self-delete correlation case ---- */

static void copy_file(const char *src, const char *dst) {
  char buf[65536];
  int in = open(src, O_RDONLY);
  int out;
  ssize_t n;

  if (in < 0)
    die("open copy source");
  out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (out < 0)
    die("open copy destination");
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    if (write(out, buf, (size_t)n) != n)
      die("write copy destination");
  }
  if (n < 0)
    die("read copy source");
  close(in);
  close(out);
}

/* Execs `exec_path` (a copy of /init) as `exec_path mode arg2 [arg3]`
 * (the --self-* child modes, see main()), lets it act once av.ko has
 * recorded the exec (calling `on_record` first, if non-NULL and the
 * record was seen), and reports how it ended and the child's pid, for
 * matching its kill line. `recorded_path` is the d_path() av.ko logs
 * for the exec (symlinks followed, through the mount it was exec'd
 * via); its event=clean line for this pid is the signal that
 * av_behavior_record_exec() has run, since av_work_fn() records before
 * it logs. The kill decision does not depend on that record - the
 * identity it matches on is committed synchronously during execve() -
 * but waiting for it puts the deletion after the exec worker, the
 * ordering most cases are about. The line is ratelimited, so if it
 * never shows the case proceeds after SELF_DELETE_RECORD_WAIT_MS
 * anyway. Returns 1 if the child was SIGKILLed. */
#define SELF_DELETE_RECORD_WAIT_MS 5000
/* av_toctou_test_delay_ms for the unlinked-before-d_path() self-delete
 * cases: long enough that the child's own unlink (its first syscall
 * after exec) always beats the parked work item's d_path(), i.e. lands
 * before av.ko has recorded anything about the exec. */
#define SELF_DELETE_EARLY_DELAY_MS 500
/* Attempts per unlinked-before-d_path() case: the fixed delay makes
 * the "(deleted)" record overwhelmingly likely, but only that log line
 * proves the ordering, so a run without it is retried, never counted. */
#define SELF_DELETE_EARLY_ATTEMPTS 3
static int run_self_delete_case(const char *exec_path, const char *mode,
                                const char *arg2, const char *arg3,
                                const char *recorded_path,
                                void (*on_record)(void), int *exit_code,
                                int *term_sig, int *saw_record,
                                pid_t *child_pid) {
  int sync_fd[2];
  pid_t pid;
  char needle[256];
  int waited = 0;

  if (pipe(sync_fd) != 0)
    die("pipe(self-delete sync)");
  pid = fork();
  if (pid < 0)
    die("fork(self-delete)");
  if (pid == 0) {
    char *const cargv[] = {(char *)exec_path, (char *)mode, (char *)arg2,
                           (char *)arg3, NULL};

    close(sync_fd[1]);
    if (sync_fd[0] != 3) {
      if (dup2(sync_fd[0], 3) < 0)
        _exit(126);
      close(sync_fd[0]);
    }
    execv(exec_path, cargv);
    _exit(127);
  }
  close(sync_fd[0]);
  *child_pid = pid;

  snprintf(needle, sizeof(needle), "path=\"%s\" pid=%d ", recorded_path,
           (int)pid);
  *saw_record = 0;
  while (waited < SELF_DELETE_RECORD_WAIT_MS) {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000L};

    if (strstr(read_kernel_log(), needle)) {
      *saw_record = 1;
      break;
    }
    nanosleep(&ts, NULL);
    waited += 50;
  }
  /* Between the record and the child's unlink: case G's retarget. */
  if (on_record && *saw_record)
    on_record();

  /* EPIPE means the child is already gone: in D/E the helper unlinks
   * its image before waiting on fd 3, so it is normally killed before
   * this write - a correct detection, judged by the wait and the
   * caller's assertions below like any other. (pid 1 never takes
   * SIGPIPE's default action, so the write returns the error rather
   * than killing init.) */
  if (write(sync_fd[1], "x", 1) != 1 && errno != EPIPE)
    die("write(self-delete sync)");
  close(sync_fd[1]);
  /* A child still running after 15s is SIGKILLed by wait_for_exit(),
   * which then reports SIGKILL: reset that so a hung child can never
   * pass for av.ko's kill. */
  if (!wait_for_exit(pid, 15000, exit_code, term_sig))
    *term_sig = 0;
  return *term_sig == SIGKILL;
}

/* Whether dmesg has av.ko's behavioral kill line for `pid` with
 * `reason` ("self-deleting binary" or "self-overwriting binary"). By
 * pid, not path: the logged name is the exec-time d_path() when the
 * exec worker had recorded it, else the path within the filesystem
 * (dentry_path_raw()), and which one depends on timing. The trailing
 * newline keeps pid=2 from matching pid=28. */
static int saw_kill_reason(pid_t pid, const char *reason) {
  char needle[160];

  snprintf(needle, sizeof(needle),
           "reason=\"%s (possible dropper/backdoor)\" pid=%d\n", reason,
           (int)pid);
  return strstr(read_kernel_log(), needle) != NULL;
}

/* Case G's on_record hook: re-point /tmp/sd_ralias from /tmp/sd_real
 * to /tmp/sd_other after av.ko has recorded the exec through it. */
static void retarget_sd_ralias(void) {
  if (unlink("/tmp/sd_ralias") != 0)
    die("unlink /tmp/sd_ralias");
  if (symlink("/tmp/sd_other", "/tmp/sd_ralias") != 0)
    die("symlink /tmp/sd_ralias -> /tmp/sd_other");
}

int main(int argc, char *const argv[]) {
  if (argc > 1 && !strcmp(argv[1], "--clean-marker")) {
    _exit(42);
  }
  /* Child halves of the self-delete cases below, run as a COPY of this
   * binary. Each blocks until the parent writes one byte to fd 3 (it
   * does so once av.ko has recorded this exec), does its one deletion,
   * then lingers so the kernel's asynchronous self-delete kill has time
   * to land. Exit 43 means it was NOT killed; 44 (sync read), 45 (the
   * deletion failed) and 46 (an exec that should fail did not) mean the
   * helper itself broke.
   *
   * --self-unlink <path>: unlink(path). */
  if (argc > 2 && !strcmp(argv[1], "--self-unlink")) {
    char c;

    if (read(3, &c, 1) != 1)
      _exit(44);
    if (unlink(argv[2]) != 0)
      _exit(45);
    sleep(5);
    _exit(43);
  }
  /* --self-unlink-early <path>: unlink(path) (this image) straight
   * away, before waiting on fd 3, while av.ko's exec work item is parked
   * by av_toctou_test_delay_ms - so the deletion lands before av.ko has
   * recorded anything for this exec, and d_path() later renders it with
   * the " (deleted)" suffix. */
  if (argc > 2 && !strcmp(argv[1], "--self-unlink-early")) {
    char c;

    if (unlink(argv[2]) != 0)
      _exit(45);
    if (read(3, &c, 1) != 1)
      _exit(44);
    sleep(5);
    _exit(43);
  }
  /* --self-rename <from> <to>: rename(from, to), replacing <to>. */
  if (argc > 3 && !strcmp(argv[1], "--self-rename")) {
    char c;

    if (read(3, &c, 1) != 1)
      _exit(44);
    if (rename(argv[2], argv[3]) != 0)
      _exit(45);
    sleep(5);
    _exit(43);
  }
  /* --self-move-unlink <from> <to>: rename(from, to) onto a free name,
   * then unlink(to). */
  if (argc > 3 && !strcmp(argv[1], "--self-move-unlink")) {
    char c;

    if (read(3, &c, 1) != 1)
      _exit(44);
    if (rename(argv[2], argv[3]) != 0 || unlink(argv[3]) != 0)
      _exit(45);
    sleep(5);
    _exit(43);
  }
  /* --self-badexec-unlink <bad> <path>: execv(bad), which must fail
   * with ENOEXEC after the kernel has already opened and checked <bad>,
   * then unlink(path). */
  if (argc > 3 && !strcmp(argv[1], "--self-badexec-unlink")) {
    char *const bargv[] = {argv[2], NULL};
    char c;

    if (read(3, &c, 1) != 1)
      _exit(44);
    execv(argv[2], bargv);
    if (errno != ENOEXEC)
      _exit(46);
    if (unlink(argv[3]) != 0)
      _exit(45);
    sleep(5);
    _exit(43);
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
  /* sysfs: the exec-time TOCTOU case below toggles av.ko's test-only
   * window knob through /sys/module/av/parameters. The initramfs may not
   * ship a /sys dir, and the rootfs is writable, so create the mountpoint
   * if needed. EEXIST just means it was already there. */
  if (mkdir("/sys", 0755) != 0 && errno != EEXIST)
    die("mkdir /sys");
  if (mount("sysfs", "/sys", "sysfs", 0, NULL) != 0 && errno != EBUSY)
    die("mount /sys");

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
   * cold_launcher.c is a dedicated, separate binary specifically so
   * the pathname it hands execve() is on a genuinely cold page: its
   * own header comment explains why init.c cannot offer that
   * guarantee itself, and the block comment at the top of this file
   * explains why a cold page no longer bypasses anything.
   *
   * Unlike the EICAR check above, nothing here touches the pathname
   * before exec - that is the whole point. Post-#94 the hook probes
   * the kernel's own exec path and hashes the pinned bprm->file, so
   * the exec must be detected and killed just like the warm one. A
   * surviving cold exec now means exec-time detection regressed. */
  {
    int killed, exited, code;
    char *log;

    write_file("/tmp/eicar_cold.com", EICAR);
    run_and_wait("/cold_launcher", NULL, &killed, &exited, &code);

    /* Rule out a broken harness before interpreting the outcome either
     * way. Exactly two shapes are meaningful: SIGKILL (the kill beat
     * the process), or cold_launcher.c's own `return 1` after its inner
     * execve() fails ENOEXEC (it exited first). Anything else - notably
     * code 127, run_and_wait's OWN outer execv() failing because
     * /cold_launcher is missing or non-executable in the initramfs -
     * says nothing about av/main.c, so it is reported as a harness
     * defect rather than folded into the detection verdict below. */
    if (!killed && !(exited && code == 1)) {
      outmsg("QEMU_TEST: FAIL: cold-pathname case is broken - "
             "/cold_launcher exited unexpectedly (exited=%d code=%d, not "
             "killed). Expected either a SIGKILL or its own exit code 1; "
             "code 127 means /cold_launcher is missing or non-executable "
             "in the initramfs. This is a defect in this harness, not in "
             "the exec hook it is aimed at.\n",
             exited, code);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    /* The dmesg verdict line, not the SIGKILL, is what this asserts.
     * The kill is workqueue-deferred, so whether it beats
     * cold_launcher.c's own exit is a separate race (that is what its
     * trailing usleep() is for) and says nothing about whether the
     * cold exec was scanned; a SIGKILL from anything other than av.ko
     * would also read as a successful detection. The substring is
     * contiguous in av_kill()'s format string and names the inner exec
     * specifically, so the EICAR check's own kill line above cannot
     * satisfy it. The path cannot pick up d_path()'s " (deleted)"
     * suffix here: nothing unlinks or renames /tmp/eicar_cold.com. */
    log = read_kernel_log();
    {
      const int detected =
          strstr(log, "action=kill type=signature "
                      "path=\"/tmp/eicar_cold.com\"") != NULL;

      if (!detected) {
        outmsg("QEMU_TEST: FAIL: the cold-pathname exec was NOT detected "
               "(killed=%d dmesg-kill-line=%d exited=%d code=%d). Since "
               "the exec hook moved onto the kernel's own exec path (#94) "
               "it hashes the pinned bprm->file and never reads the "
               "pathname from userspace, so a cold page cannot excuse "
               "this: either exec-time detection regressed, or the hook "
               "is not registered at all - av.ko logs 'exec hook "
               "registered on <symbol>' at insmod, and logs every "
               "candidate it could not probe. Do not relax this check "
               "to make it pass.\n",
               killed, detected, exited, code);
        outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", log);
        poweroff_now();
        return 1;
      }
      outmsg("QEMU_TEST: cold-pathname exec detected on a guaranteed-cold "
             "pathname page (killed=%d exited=%d code=%d) - issue #2's "
             "cold-page bypass stays closed\n",
             killed, exited, code);
    }
  }
  /* Fixed marker, separate from the line above (which carries run
   * detail): qemu-boot-test.yml greps for exactly this so the case
   * cannot be deleted or #if'd out of here and still produce a green
   * PASS. Same pattern as the TOCTOU and #48 cases below. */
  outmsg("QEMU_TEST: cold-pathname regression check passed\n");

  /* ---- regression cases: self-delete detection (#230) ----
   * av.ko kills a process that unlinks the directory entry it was
   * exec'd from, or renames another file over it. The decision is made
   * in kprobes on security_inode_unlink()/security_inode_rename(), by
   * comparing the dentry the kernel resolved for the deletion against
   * the one this process was exec'd from (see struct av_exec_ident in
   * av/behavior.c). It used to compare path strings, which every
   * spelling of the name the kernel resolves differently - directory
   * symlinks, "..", bind mounts, /proc/<pid>/cwd - could defeat in one
   * direction or the other; cases A-M and P below are each one of
   * those spellings.
   *
   * All of these wait until av.ko's exec worker has recorded the exec
   * before deleting. Kills must carry the expected reason; non-kills
   * must exit 43 (the helper ran and survived), so a broken helper
   * cannot pass for a correct non-kill. */
  {
    static const struct {
      const char *name;     /* /tmp/sd_real/<name> is the image */
      const char *exec;     /* the name it is exec'd by */
      const char *recorded; /* d_path() av.ko logs for it */
      const char *link;     /* hard link to make to the image, or NULL */
      const char *mode;
      const char *arg2, *arg3;
      const char *reason; /* expected kill reason, NULL = not killed */
      const char *survivor; /* must still exist afterwards, or NULL */
      const char *what;
    } cases[] = {
        {"a", "/tmp/sd_alias/a", "/tmp/sd_real/a", NULL, "--self-unlink",
         "/tmp/sd_alias/a", NULL, "self-deleting binary", NULL,
         "exec via dir symlink, unlink via it"},
        {"b", "/tmp/sd_alias/b", "/tmp/sd_real/b", NULL, "--self-unlink",
         "/tmp/sd_real/b", NULL, "self-deleting binary", NULL,
         "exec via dir symlink, unlink via real dir"},
        {"c", "/tmp/sd_alias/c", "/tmp/sd_real/c", NULL, "--self-unlink",
         "/tmp/sd_real/c_other", NULL, NULL, "/tmp/sd_real/c",
         "control: unlink an unrelated file"},
        {"i", "/tmp/sd_real/i", "/tmp/sd_real/i", NULL, "--self-unlink",
         "/tmp/sd_alias/i", NULL, "self-deleting binary", NULL,
         "exec via real dir, unlink via dir symlink"},
        {"j", "/tmp/sd_real/j", "/tmp/sd_real/j", NULL, "--self-unlink",
         "/proc/self/cwd/tmp/sd_real/j", NULL, "self-deleting binary", NULL,
         "unlink via /proc/self/cwd"},
        {"k", "/tmp/sd_real/k", "/tmp/sd_real/k", "/tmp/sd_real/k_link",
         "--self-unlink", "/tmp/sd_real/k_link", NULL, NULL,
         "/tmp/sd_real/k", "hard link: unlink the OTHER name"},
        {"l", "/tmp/sd_real/l", "/tmp/sd_real/l", "/tmp/sd_real/l_keep",
         "--self-unlink", "/tmp/sd_real/l", NULL, "self-deleting binary",
         "/tmp/sd_real/l_keep", "hard link: unlink the exec'd name"},
        {"m", "/tmp/sd_bind/m", "/tmp/sd_bind/m", NULL, "--self-unlink",
         "/tmp/sd_real/m", NULL, "self-deleting binary", NULL,
         "exec via bind mount, unlink via original"},
        {"n", "/tmp/sd_real/n", "/tmp/sd_real/n", NULL, "--self-rename",
         "/tmp/sd_real/n_decoy", "/tmp/sd_real/n", "self-overwriting binary",
         NULL, "rename a decoy over own image"},
        {"o", "/tmp/sd_real/o", "/tmp/sd_real/o", NULL, "--self-rename",
         "/tmp/sd_real/o_decoy", "/tmp/sd_real/o_other", NULL,
         "/tmp/sd_real/o", "control: rename a decoy over an unrelated file"},
        {"p", "/tmp/sd_real/p", "/tmp/sd_real/p", NULL, "--self-move-unlink",
         "/tmp/sd_real/p", "/tmp/sd_alias/p_moved", "self-deleting binary",
         NULL, "rename own image away, unlink the new name"},
        {"q", "/tmp/sd_real/q", "/tmp/sd_real/q", NULL,
         "--self-badexec-unlink", "/tmp/sd_real/q_bad", "/tmp/sd_real/q",
         "self-deleting binary", NULL,
         "failed execve() of another file, then unlink own image"},
    };
    int failed = 0;

    if (mkdir("/tmp/sd_real", 0755) != 0)
      die("mkdir /tmp/sd_real");
    if (symlink("/tmp/sd_real", "/tmp/sd_alias") != 0)
      die("symlink /tmp/sd_alias");
    if (mkdir("/tmp/sd_bind", 0755) != 0)
      die("mkdir /tmp/sd_bind");
    if (mount("/tmp/sd_real", "/tmp/sd_bind", NULL, MS_BIND, NULL) != 0)
      die("bind mount /tmp/sd_real on /tmp/sd_bind");
    write_file("/tmp/sd_real/c_other", "not the executable\n");
    write_file("/tmp/sd_real/n_decoy", "decoy\n");
    write_file("/tmp/sd_real/o_decoy", "decoy\n");
    write_file("/tmp/sd_real/o_other", "not the executable\n");
    /* No ELF magic, no "#!": every binfmt declines it with ENOEXEC,
     * after security_bprm_check() has already seen it. */
    write_file("/tmp/sd_real/q_bad", "not an executable format\n");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      char real[64];
      int code, sig, saw_record, killed;
      pid_t child;
      struct stat st;

      snprintf(real, sizeof(real), "/tmp/sd_real/%s", cases[i].name);
      copy_file("/init", real);
      if (cases[i].link && link(real, cases[i].link) != 0)
        die("link self-delete case image");
      killed = run_self_delete_case(cases[i].exec, cases[i].mode,
                                    cases[i].arg2, cases[i].arg3,
                                    cases[i].recorded, NULL, &code, &sig,
                                    &saw_record, &child);
      outmsg("QEMU_TEST: self-delete case %s (%s): exec %s, %s %s%s%s -> "
             "%s (exit=%d sig=%d, exec record %s)\n",
             cases[i].name, cases[i].what, cases[i].exec, cases[i].mode,
             cases[i].arg2, cases[i].arg3 ? " " : "",
             cases[i].arg3 ? cases[i].arg3 : "",
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      if (!saw_record) {
        /* Without the record the deletion may have run before the
         * exec worker - not the ordering these cases are about. */
        outmsg("QEMU_TEST: FAIL: self-delete case %s never logged its "
               "exec record\n",
               cases[i].name);
        failed = 1;
      } else if (killed != (cases[i].reason != NULL)) {
        outmsg("QEMU_TEST: FAIL: self-delete case %s expected %s\n",
               cases[i].name, cases[i].reason ? "a kill" : "no kill");
        failed = 1;
      } else if (!killed && code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete case %s exited %d, not 43 - "
               "the helper itself broke (44 = sync read, 45 = the "
               "deletion, 46 = exec did not fail with ENOEXEC)\n",
               cases[i].name, code);
        failed = 1;
      } else if (killed && !saw_kill_reason(child, cases[i].reason)) {
        outmsg("QEMU_TEST: FAIL: self-delete case %s was killed but dmesg "
               "has no reason=\"%s ...\" pid=%d line\n",
               cases[i].name, cases[i].reason, (int)child);
        failed = 1;
      } else if (cases[i].survivor && stat(cases[i].survivor, &st) != 0) {
        outmsg("QEMU_TEST: FAIL: self-delete case %s removed %s, which "
               "the case needs to survive\n",
               cases[i].name, cases[i].survivor);
        failed = 1;
      }
    }
    /* av.ko keeps the exec'd dentry only as a compared cookie, never a
     * reference: a held dentry or vfsmount would make this -EBUSY. The
     * exec worker's own file reference is dropped just after it logs
     * the record, so allow it a moment. */
    if (!failed) {
      int tries = 0;

      while (umount2("/tmp/sd_bind", 0) != 0) {
        if (errno != EBUSY || ++tries >= 40) {
          outmsg("QEMU_TEST: FAIL: umount /tmp/sd_bind after the "
                 "self-delete cases: %s\n",
                 strerror(errno));
          failed = 1;
          break;
        }
        {
          struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000L};
          nanosleep(&ts, NULL);
        }
      }
    }
    /* D/E: the image unlinked as the child's first syscall, before
     * av.ko's exec worker has run at all - the knob parks it, and the
     * " (deleted)" suffix on its eventual record proves the unlink came
     * first (a run without it is retried, never counted). The identity
     * the unlink is matched against is committed during execve() itself
     * (setup_new_exec()), so this is still a kill. When
     * self-delete matching compared path strings recorded by that
     * worker, this ordering had to be handled separately (CodeRabbit on
     * #110).
     *
     *   D: exec via the dir symlink, unlink via it    -> killed
     *   E: exec via the dir symlink, unlink via real dir -> killed */
    if (!failed) {
      static const struct {
        const char *name;
        const char *unlink;
      } early[] = {
          {"d", "/tmp/sd_alias/d"},
          {"e", "/tmp/sd_real/e"},
      };

      write_param_int(TOCTOU_DELAY_PARAM, SELF_DELETE_EARLY_DELAY_MS);
      for (size_t i = 0; i < sizeof(early) / sizeof(early[0]); i++) {
        char real[64], alias[64], recorded[80];
        int code, sig, saw_record, killed;
        pid_t child;

        snprintf(real, sizeof(real), "/tmp/sd_real/%s", early[i].name);
        snprintf(alias, sizeof(alias), "/tmp/sd_alias/%s", early[i].name);
        snprintf(recorded, sizeof(recorded), "%s (deleted)", real);
        for (int attempt = 0; attempt < SELF_DELETE_EARLY_ATTEMPTS;
             attempt++) {
          copy_file("/init", real);
          killed = run_self_delete_case(alias, "--self-unlink-early",
                                        early[i].unlink, NULL, recorded, NULL,
                                        &code, &sig, &saw_record, &child);
          if (saw_record)
            break;
          outmsg("QEMU_TEST: self-delete case %s attempt %d: no \"%s\" "
                 "record, retrying\n",
                 early[i].name, attempt + 1, recorded);
        }
        outmsg("QEMU_TEST: self-delete case %s (unlinked before the exec "
               "worker ran): exec %s, unlink %s -> %s (exit=%d sig=%d, "
               "\"(deleted)\" record %s)\n",
               early[i].name, alias, early[i].unlink,
               killed ? "killed" : "not killed", code, sig,
               saw_record ? "seen" : "not seen in log");
        if (!saw_record) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s never logged the "
                 "\"%s\" record in %d attempts - the unlink-before-record "
                 "ordering it tests was not reached\n",
                 early[i].name, recorded, SELF_DELETE_EARLY_ATTEMPTS);
          failed = 1;
        } else if (!killed) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s expected a kill%s\n",
                 early[i].name,
                 code == 45 ? " (helper's unlink failed)" : "");
          failed = 1;
        } else if (!saw_kill_reason(child, "self-deleting binary")) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s was killed but dmesg "
                 "has no reason=\"self-deleting binary ...\" pid=%d line\n",
                 early[i].name, (int)child);
          failed = 1;
        }
      }
      write_param_int(TOCTOU_DELAY_PARAM, 0);
    }
    /* F: exec through a symlink to the FILE (/tmp/sd_flink/f ->
     * /tmp/sd_real/f, /tmp/sd_flink a real directory), then unlink that
     * symlink -> NOT killed: it removes the symlink, not the image. A
     * path-string match on "same final name" killed here (CodeRabbit on
     * x86 #229); the symlink's own dentry never matches the image's. */
    if (!failed) {
      int code, sig, saw_record, killed;
      pid_t child;

      if (mkdir("/tmp/sd_flink", 0755) != 0)
        die("mkdir /tmp/sd_flink");
      copy_file("/init", "/tmp/sd_real/f");
      if (symlink("/tmp/sd_real/f", "/tmp/sd_flink/f") != 0)
        die("symlink /tmp/sd_flink/f");
      killed = run_self_delete_case("/tmp/sd_flink/f", "--self-unlink",
                                    "/tmp/sd_flink/f", NULL, "/tmp/sd_real/f",
                                    NULL, &code, &sig, &saw_record, &child);
      outmsg("QEMU_TEST: self-delete case f (file symlink, same name): "
             "exec /tmp/sd_flink/f, unlink /tmp/sd_flink/f -> %s "
             "(exit=%d sig=%d, exec record %s)\n",
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      if (!saw_record || killed || code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete case f expected a seen exec "
               "record, no kill and exit 43 (44 = sync read, 45 = "
               "unlink)\n");
        failed = 1;
      }
    }
    /* G: exec through a directory alias, then point the alias somewhere
     * else before unlinking through it -> NOT killed. /tmp/sd_ralias ->
     * /tmp/sd_real at exec; once the record exists the parent re-points
     * the alias at /tmp/sd_other, which holds its own "g", and the
     * child's unlink removes that one. The unlink spelling is the same
     * as the exec's, which a path-string match killed on (CodeRabbit on
     * #229); the dentry it resolves to now is a different one. */
    if (!failed) {
      int code, sig, saw_record, killed;
      pid_t child;
      struct stat st;

      if (mkdir("/tmp/sd_other", 0755) != 0)
        die("mkdir /tmp/sd_other");
      if (symlink("/tmp/sd_real", "/tmp/sd_ralias") != 0)
        die("symlink /tmp/sd_ralias");
      copy_file("/init", "/tmp/sd_real/g");
      copy_file("/init", "/tmp/sd_other/g");
      killed = run_self_delete_case("/tmp/sd_ralias/g", "--self-unlink",
                                    "/tmp/sd_ralias/g", NULL,
                                    "/tmp/sd_real/g", retarget_sd_ralias,
                                    &code, &sig, &saw_record, &child);
      outmsg("QEMU_TEST: self-delete case g (alias retargeted after exec): "
             "exec /tmp/sd_ralias/g, alias -> /tmp/sd_other, unlink "
             "/tmp/sd_ralias/g -> %s (exit=%d sig=%d, exec record %s)\n",
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      if (!saw_record || killed || code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete case g expected a seen exec "
               "record, no kill and exit 43 (44 = sync read, 45 = "
               "unlink)\n");
        failed = 1;
      } else if (stat("/tmp/sd_real/g", &st) != 0 ||
                 stat("/tmp/sd_other/g", &st) == 0) {
        outmsg("QEMU_TEST: FAIL: self-delete case g's unlink did not "
               "remove /tmp/sd_other/g and leave /tmp/sd_real/g - the "
               "retarget did not take effect\n");
        failed = 1;
      }
    }
    /* H: exec through a directory symlink, then unlink through that
     * symlink followed by ".." -> NOT killed. /tmp/sd_hx/link ->
     * /tmp/sd_hy/sub; the child execs /tmp/sd_hx/link/h and unlinks
     * /tmp/sd_hx/link/../link/h. That collapses lexically to the exec's
     * own spelling, but the kernel follows the link before the "..", so
     * the unlink removes /tmp/sd_hy/link/h and the image is untouched
     * (CodeRabbit on x86 #229). */
    if (!failed) {
      int code, sig, saw_record, killed;
      pid_t child;
      struct stat st;

      if (mkdir("/tmp/sd_hx", 0755) != 0 || mkdir("/tmp/sd_hy", 0755) != 0 ||
          mkdir("/tmp/sd_hy/sub", 0755) != 0 ||
          mkdir("/tmp/sd_hy/link", 0755) != 0)
        die("mkdir case h dirs");
      if (symlink("/tmp/sd_hy/sub", "/tmp/sd_hx/link") != 0)
        die("symlink /tmp/sd_hx/link");
      copy_file("/init", "/tmp/sd_hy/sub/h");
      copy_file("/init", "/tmp/sd_hy/link/h");
      killed = run_self_delete_case(
          "/tmp/sd_hx/link/h", "--self-unlink", "/tmp/sd_hx/link/../link/h",
          NULL, "/tmp/sd_hy/sub/h", NULL, &code, &sig, &saw_record, &child);
      outmsg("QEMU_TEST: self-delete case h (\"..\" after a dir symlink): "
             "exec /tmp/sd_hx/link/h, unlink /tmp/sd_hx/link/../link/h -> "
             "%s (exit=%d sig=%d, exec record %s)\n",
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      if (!saw_record || killed || code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete case h expected a seen exec "
               "record, no kill and exit 43 (44 = sync read, 45 = "
               "unlink)\n");
        failed = 1;
      } else if (stat("/tmp/sd_hy/sub/h", &st) != 0 ||
                 stat("/tmp/sd_hy/link/h", &st) == 0) {
        outmsg("QEMU_TEST: FAIL: self-delete case h's unlink did not "
               "remove /tmp/sd_hy/link/h and leave /tmp/sd_hy/sub/h - the "
               "\"..\" did not resolve physically\n");
        failed = 1;
      }
    }
    if (failed) {
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }
  }
  /* Fixed marker for qemu-boot-test.yml - see the cold-pathname one. */
  outmsg("QEMU_TEST: self-delete correlation check passed\n");

  /* ---- Regression case: exec-time TOCTOU (issue #45, the second half
   * of #2) ----
   *
   * av/main.c's av_work_fn() comment is the authoritative writeup. The
   * kprobe pins bprm->file - the struct file the kernel is executing -
   * and the hash is taken from THAT, so renaming a clean decoy over the
   * path cannot change what gets scanned. Before #94 the kprobe captured
   * only the pathname STRING at execve() time and the workqueue did a
   * separate, later open of it; nothing tied the two to the same inode,
   * and a rename landing in that window got the decoy hashed while the
   * EICAR that executed went unreported.
   *
   * Run as a batch: TOCTOU_SWAP_ATTEMPTS swap attempts, each interleaved
   * with a no-swap control, verdict over the batch. Two mechanisms make
   * every attempt DETERMINISTIC rather than a timing gamble (see the
   * block comment at the top of this file for the full rationale, and
   * for why the earlier fire-from-the-parent-and-hope version was
   * unsound):
   *
   *   - A sync pipe orders the swap relative to the exec. The child
   *     execve()s, then writes its resulting errno to the pipe; the parent
   *     blocks reading that value and only then renames. The rename is
   *     therefore guaranteed to land AFTER the exec has already resolved
   *     and opened EICAR, so the swap always exercises the real post-exec
   *     window and never the fork->exec window. The errno (ENOEXEC -
   *     EICAR is not an ELF) is ground truth that the exec resolved EICAR
   *     and not the decoy; the parent checks it and refuses to draw any
   *     conclusion from an attempt that broke.
   *
   *   - av.ko's test-only av_toctou_test_delay_ms knob, set to
   *     TOCTOU_WQ_DELAY_MS for the duration of this batch only (0 for
   *     every other exec in this boot and in all production), parks the
   *     work item before it d_path()s and hashes so the rename is
   *     certain to land mid-scan. Without it the scan completes inside the failing
   *     execve() syscall (measured: renaming after execve returns is
   *     already too late) and the swap would be asserting nothing.
   *
   * Same-directory rename is atomic, so nothing here can observe a
   * half-state. It does unlink the dentry of the pinned inode, which is
   * why the kill line for a swap may render the path with d_path()'s
   * " (deleted)" suffix - see the match built below. */
  {
    int i;
    int decoy_wins = 0;    /* swap: exec saw EICAR, scanner hashed the decoy - the bug */
    int swap_kills = 0;    /* swap: exec saw EICAR, scanner killed on it - required */
    int swap_lost = 0;     /* swap: neither line for this pid (work dropped) */
    int control_kills = 0; /* control: un-swapped EICAR detected+killed, as it must be */
    int control_bad = 0;   /* control: un-swapped EICAR NOT killed - a broken fixture */
    int exec_errno_bad = 0;/* either arm: exec did not fail ENOEXEC - a sync/fixture defect */

    /* Park the deferred hash for this batch only, so every swap lands
     * mid-scan (see TOCTOU_WQ_DELAY_MS), then restore production timing
     * (below) before the #48 section - or anything else - execs. */
    write_param_int(TOCTOU_DELAY_PARAM, TOCTOU_WQ_DELAY_MS);

    for (i = 0; i < TOCTOU_SWAP_ATTEMPTS; i++) {
      char target[64], decoy[64];
      char kill_line[160], kill_line_deleted[176], decoy_line[224];
      int swap;
      char *log;

      /* Two attempts per iteration: one control (no swap), one swap.
       * Interleaved rather than run as two separate loops so both arms
       * see identical workqueue/scheduler conditions - a control that
       * ran while the queue was quiet and a swap that ran while it was
       * busy would not be comparable. */
      for (swap = 0; swap <= 1; swap++) {
        pid_t pid;
        int status;
        int sync_pipe[2];
        int exec_errno = 0;
        ssize_t r;

        snprintf(target, sizeof(target), "/tmp/tc_%s_%d",
                 swap ? "swap" : "ctl", i);
        snprintf(decoy, sizeof(decoy), "/tmp/tc_decoy_%d", i);
        write_file(target, EICAR);
        if (swap)
          write_file(decoy, TOCTOU_DECOY_BYTES);

        if (pipe(sync_pipe) != 0)
          die("pipe(toctou)");

        pid = fork();
        if (pid < 0)
          die("fork(toctou)");
        if (pid == 0) {
          char *const a[] = {target, NULL};
          int e;

          close(sync_pipe[0]); /* child only writes the exec result */

          /* Fault the pathname page in first (same reasoning as
           * run_and_wait()): this case is about the inode race, not the
           * cold-page gap, so that variable is kept out of it. */
          volatile char t = target[0];
          (void)t;
          execv(target, a);
          e = errno; /* EICAR is not an ELF, so execv() always fails ENOEXEC */

          /* Report the exec result, THEN linger. The write is both the
           * ground-truth signal (which errno == which inode the kernel
           * resolved for this exec) and the ordering edge the parent
           * blocks on before renaming, so the rename cannot precede the
           * exec. Sent before lingering (not via the exit status) so the
           * parent has it even when the scanner SIGKILLs this child
           * mid-linger - the fixed-scanner / CLOSED==1 case. */
          if (write(sync_pipe[1], &e, sizeof(e)) != (ssize_t)sizeof(e))
            _exit(2);
          close(sync_pipe[1]);

          /* Linger so the (delayed) workqueue opens, hashes and logs its
           * verdict for this path while the pid is still live and cannot
           * be reused. Must outlast the injected open delay plus the hash;
           * TOCTOU_LINGER_US is TOCTOU_WQ_DELAY_MS + a wide margin. A
           * killed EICAR child exits as soon as the SIGKILL arrives, far
           * sooner. */
          usleep(TOCTOU_LINGER_US);
          _exit(1);
        }
        close(sync_pipe[1]); /* parent only reads */

        /* Block until the child reports its execve result. This is the
         * ordering edge that removes the old (A)-vs-(B) confound: the
         * rename below cannot run until exec has already entered and
         * resolved the path, so at exec-entry the path was still the
         * original file. For a swap that file is EICAR (exec_errno ==
         * ENOEXEC), so any later decoy hash is unambiguously ordering
         * (B) - the kprobe->workqueue window - not a benign pre-exec
         * swap. */
        r = read(sync_pipe[0], &exec_errno, sizeof(exec_errno));
        close(sync_pipe[0]);
        if (r != (ssize_t)sizeof(exec_errno)) {
          kill(pid, SIGKILL);
          waitpid(pid, &status, 0);
          die("read(toctou sync)");
        }

        /* The race itself, now strictly after exec-entry. rename()
         * returns immediately; whether it lands before or after the
         * (delay-widened) workqueue open() is what this measures. A
         * failed rename is a fixture defect, not a data point: the swap
         * would silently degrade into a second control, get a kill line,
         * and be counted in swap_kills - i.e. a batch where every rename
         * failed would pass as "the TOCTOU stays closed" without ever
         * having raced anything. Fail loudly instead (see the vacuity
         * guard note below). */
        if (swap && rename(decoy, target) != 0) {
          int saved = errno;
          kill(pid, SIGKILL);
          waitpid(pid, &status, 0);
          errno = saved;
          die("rename(toctou decoy)");
        }

        if (waitpid(pid, &status, 0) < 0)
          die("waitpid(toctou)");
        /* The verdict LINE is the signal, not the SIGKILL: whether the
         * kill beats the child's own exit is a separate race and
         * irrelevant to which inode was hashed. Classifying on the exit
         * status would misfile a detected control as broken whenever the
         * child happened to exit first. */

        log = read_kernel_log();
        /* Two spellings, both exact (closing quote included) so
         * /tmp/tc_swap_1 cannot be satisfied by /tmp/tc_swap_10's line.
         * The swap's rename() unlinks the dentry of the inode the kprobe
         * pinned, so d_path() renders that still-open file as
         * "<target> (deleted)" if the rename beat av_work_fn()'s
         * d_path() call and as plain "<target>" if it did not - a race
         * this case has no reason to pin down, since both spellings name
         * the same executed inode. The control arm renames nothing and
         * only ever produces the plain form. Matching just the prefix
         * instead would be simpler and wrong in the dangerous
         * direction. */
        snprintf(kill_line, sizeof(kill_line),
                 "action=kill type=signature path=\"%s\"", target);
        snprintf(kill_line_deleted, sizeof(kill_line_deleted),
                 "action=kill type=signature path=\"%s (deleted)\"", target);
        /* Prefix through sha256= only - the trailing " err=..." is left
         * off so the match does not depend on the exact fail-open errno.
         * pid pins the line to THIS attempt, so an earlier iteration's
         * line for a different path/pid cannot satisfy it. */
        snprintf(decoy_line, sizeof(decoy_line),
                 "event=clean type=fail-open path=\"%s\" pid=%d "
                 "md5= sha1= sha256=%s",
                 target, (int)pid, TOCTOU_DECOY_SHA256);

        /* Ground truth: which inode was live when the kernel entered this
         * exec. Both samples are non-ELF, so the original file (EICAR, and
         * the decoy too) yields ENOEXEC. Anything else means the child
         * never reached a clean execve on the intended path - a sync or
         * fixture defect that would make the swap/control tallies
         * meaningless, so it is failed loudly rather than classified. The
         * sync pipe guarantees the swap rename ran after exec-entry, so a
         * swap must also see ENOEXEC. */
        if (exec_errno != ENOEXEC) {
          exec_errno_bad++;
          continue;
        }

        if (swap) {
          if (strstr(log, decoy_line))
            decoy_wins++;
          else if (strstr(log, kill_line) || strstr(log, kill_line_deleted))
            swap_kills++;
          else
            swap_lost++;
        } else {
          if (strstr(log, kill_line))
            control_kills++;
          else
            control_bad++;
        }
      }
    }

    /* Restore production timing before anything else (e.g. #48) execs. */
    write_param_int(TOCTOU_DELAY_PARAM, 0);

    outmsg("QEMU_TEST: toctou batch: attempts=%d decoy_wins=%d "
           "swap_kills=%d swap_lost=%d control_kills=%d control_bad=%d "
           "exec_errno_bad=%d\n",
           TOCTOU_SWAP_ATTEMPTS, decoy_wins, swap_kills, swap_lost,
           control_kills, control_bad, exec_errno_bad);

    /* Ground-truth guard first - if any exec did not fail ENOEXEC, the
     * child never cleanly reached execve on the intended path, so the
     * sync-pipe ordering that the whole case rests on did not hold and no
     * tally below can be trusted. This is distinct from a broken control:
     * it says the experiment itself did not run, not that detection
     * failed. */
    if (exec_errno_bad != 0) {
      outmsg("QEMU_TEST: FAIL: %d of %d toctou execs did not fail ENOEXEC "
             "as expected - the child did not cleanly reach execve on the "
             "intended path, so the sync-pipe ordering this case relies on "
             "did not hold and the swap/control tallies are meaningless. "
             "This is a harness defect, not evidence about the #2 TOCTOU.\n",
             exec_errno_bad, TOCTOU_SWAP_ATTEMPTS * 2);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    /* Vacuity guard - if the control does not reliably detect and kill
     * an un-swapped EICAR, nothing else in this case means anything (see
     * the block comment at the top of this file). This is the #34/#45
     * lesson: a fixture that cannot reproduce what it claims must fail
     * loudly, not pass quietly. */
    if (control_bad != 0) {
      outmsg("QEMU_TEST: FAIL: toctou control is broken - %d of %d "
             "un-swapped EICAR execs were NOT detected+killed. The swap "
             "results below cannot be trusted until an un-raced EICAR is "
             "reliably caught; this is a harness/detection defect, not "
             "evidence about the #2 TOCTOU.\n",
             control_bad, TOCTOU_SWAP_ATTEMPTS);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    /* swap_lost is neither a decoy-hash nor a kill: the exec produced no
     * verdict line at all (e.g. av_work_admit() refused it under load).
     * It is not itself a failure, but a batch that is mostly lost has
     * measured nothing, so guard against it silently hollowing out the
     * verdict. A sudden jump here with decoy_wins still 0 is also how a
     * path-match regression would show up - if the kill line's path
     * stopped matching either spelling built above, every swap would land
     * in this bucket. */
    if (swap_lost > TOCTOU_SWAP_ATTEMPTS / 2) {
      outmsg("QEMU_TEST: FAIL: toctou batch inconclusive - %d of %d swap "
             "attempts produced neither a decoy-hash nor a kill line, so "
             "the race window was never actually exercised\n",
             swap_lost, TOCTOU_SWAP_ATTEMPTS);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    /* The assertion: not one swap may get the decoy hashed. Every swap
     * was ordered strictly after exec entry (sync pipe) with the decoy
     * renamed over the path while the scan was parked mid-flight, so a
     * single decoy-hash line means the verdict came from the pathname
     * rather than from the inode that executed - i.e. #94's fix came
     * undone. */
    if (decoy_wins != 0) {
      outmsg("QEMU_TEST: FAIL: %d of %d swap attempt(s) got the scanner to "
             "hash the decoy even though exec saw EICAR at entry (every exec "
             "failed ENOEXEC) and the rename was ordered strictly after exec "
             "entry. Since #94 the exec verdict is taken from the pinned "
             "bprm->file, so a swap cannot change what is hashed: the hook "
             "has gone back to scanning a path rather than the executed "
             "file. This is issue #2/#45 reopening - do not relax this "
             "check.\n",
             decoy_wins, TOCTOU_SWAP_ATTEMPTS);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    /* And the swaps must be caught, not merely not-fooled: with the
     * decoy ruled out, every attempt that produced a verdict line
     * produced a kill on the EICAR that executed. swap_lost is already
     * bounded above, so requiring a strict majority here is what stops a
     * batch of mostly-dropped work from reading as a clean pass. */
    if (swap_kills <= TOCTOU_SWAP_ATTEMPTS / 2) {
      outmsg("QEMU_TEST: FAIL: only %d of %d swap attempts were "
             "detected+killed (decoy_wins=0, swap_lost=%d). No attempt was "
             "fooled by the decoy, so the hash is still coming from the "
             "executed inode, but too few attempts produced a kill line to "
             "call the case exercised - check whether the verdict lines are "
             "being emitted at all and whether the param write to "
             TOCTOU_DELAY_PARAM " took effect.\n",
             swap_kills, TOCTOU_SWAP_ATTEMPTS, swap_lost);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      poweroff_now();
      return 1;
    }

    outmsg("QEMU_TEST: exec-time TOCTOU stays closed - 0/%d swap attempts "
           "hashed the decoy, %d were killed on the exec'd EICAR "
           "(swap_lost=%d), controls killed %d/%d\n",
           TOCTOU_SWAP_ATTEMPTS, swap_kills, swap_lost, control_kills,
           TOCTOU_SWAP_ATTEMPTS);
  }
  outmsg("QEMU_TEST: TOCTOU regression check passed\n");

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
     * execs a file whose scan cannot conclude in that budget: 1.5KB of
     * identical bytes against tests/fixtures/fail_closed_slow.yar's
     * three calibration rules, whose nested quantifiers need ~1.35s on
     * libyara 4.5.x while matching nothing (no 'b' present, so no
     * conviction regardless of score - and weight=1 could never convict
     * alone anyway). perform_scan() reports CLEAN with incomplete=1,
     * and the handler must deny it because the flag is set.
     *
     * Same errno discipline as the verdict case: both samples are
     * non-ELF, so the only variable is ENOEXEC (allowed through to
     * binfmt) vs EPERM (the gate denied pre-exec). Attribution comes
     * from the same two controls: the first avd's clean file staying
     * ENOEXEC, and avd's own end-of-run tally ("1 allowed, ... 1
     * undecided") showing the slow file denied without a detection -
     * the incomplete branch counts there by design, not under denied.
     *
     * Non-vacuity, per #45: the small-clean control below proves the
     * 1s budget does not deny everything, and the verdict case's
     * ENOEXEC baseline proves clean content reaches binfmt ungated. If
     * the incomplete branch ever stops consulting the flag, the slow
     * file reads ENOEXEC where EPERM is asserted and this fails.
     */
    {
      const char *slow = "/tmp/gate_slow";
      const char *slow_clean = "/tmp/gate_slow_clean";
      pid_t fc_pid;
      int fc_pipe[2];
      char *fc_out;
      int fc_denied = 0;
      struct timespec fc_start;
      int fc_err = -1, fc_killed = 0;

      write_repeated(slow, 'a', 1536);
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
        /* 1s budget: the slow file needs ~1.35s, small files need ~1ms
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
       * under TCG.
       *
       * Wall-clock deadline, not an iteration count: each
       * exec_expect_failure() here blocks for the full 1s YARA
       * budget while the gate is not yet denying (vs ~1ms per exec
       * in the verdict case above), so a fixed += 200 per iteration
       * would undercount real time ~6x and let the loop run past the
       * workflow's outer QEMU timeout - turning the intended
       * "never denied" FAIL below into an opaque harness timeout. */
      clock_gettime(CLOCK_MONOTONIC, &fc_start);
      for (;;) {
        struct timespec now;
        long elapsed_ms;
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
        write_repeated(slow, 'a', 1536);
        exec_expect_failure(slow, &err, &killed);
        last_err = err;
        last_killed = killed;
        if (!killed && err == EPERM) {
          fc_denied = 1;
          break;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_ms = (now.tv_sec - fc_start.tv_sec) * 1000L +
                     (now.tv_nsec - fc_start.tv_nsec) / 1000000L;
        if (elapsed_ms >= deadline_ms)
          break;
        {
          struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000L};
          nanosleep(&ts, NULL);
        }
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
      /* 60s, not 15s: under TCG the fail-closed avd's orderly teardown
       * takes ~14.5s (joining scan workers after a timed-out YARA
       * scan, YARA teardown, gate stop - all wall-clock slow under
       * emulation), so a 15s grace has under a second of margin and
       * flakes red on ordinary run-to-run jitter. Observed: the same
       * commit shut down in ~14.5s (pass) and ~15.2s (FAIL) on the
       * 7.2.6 leg across two runs. A genuinely stuck shutdown still
       * never exits, so the wider grace keeps the stuck-detection
       * property while absorbing emulator slowness. */
      if (!wait_for_exit(fc_pid, 60000, &code, &sig)) {
        outmsg("QEMU_TEST: FAIL: fail-closed avd did not exit within 60s "
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
      /* The per-event "did not complete" line goes to stderr, which
       * stays on the console (see the set-up comment where avd is
       * forked) - it is visible in the serial log above, not in this
       * pipe. What stdout carries is the gate's end-of-run tally,
       * where the incomplete-scan deny lands in the undecided column
       * by design (nothing was detected - see fanexec_handle_event()'s
       * comment). The exact tally is the assertion: "1 allowed" is
       * the small-clean control, "1 undecided" is the slow file
       * denied without a detection, "0 denied" rules out any
       * conviction path producing the EPERM. A fail-open regression
       * reads "2 allowed, 0 undecided" and fails here, same as at the
       * errno assertions above. */
      if (!strstr(fc_out, "1 allowed, 0 denied, 1 undecided")) {
        outmsg("QEMU_TEST: FAIL: fail-closed avd's tally is not \"1 "
               "allowed, 0 denied, 1 undecided\" - the slow exec's EPERM "
               "did not come from the incomplete-scan branch\n");
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
