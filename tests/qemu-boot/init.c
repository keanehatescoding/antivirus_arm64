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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define EICAR                                                                \
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

/* Expected outcome of the cold-pathname bypass case near the end of
 * main(). That case used to print its result and gate nothing, which
 * meant it could also rot into a silent no-op (a missing or
 * non-executable /cold_launcher exits 127, which read as "not killed",
 * i.e. indistinguishable from the bypass it is supposed to be
 * detecting). It gates now, in both directions:
 *
 *   1 = the gap is still OPEN - the current, documented state (issue
 *       #2, discussion #33, and handler_pre()'s comment in av/main.c).
 *       The bypass MUST reproduce. If it stops reproducing, that is
 *       good news, but it fails the build anyway so the expectation
 *       and the docs get flipped deliberately instead of quietly
 *       drifting out of date.
 *   0 = the gap is CLOSED - /cold_launcher MUST be killed, and a
 *       surviving cold exec is a regression.
 *
 * Flip this to 0 in the same change that closes the gap, together with
 * SECURITY.md's accepted-tradeoffs list and docs/evasion-findings.md
 * (whose own finding #4 is explicitly about re-running adversarial
 * tests after a fix rather than assuming them), plus the wiki's CI
 * and Packaging page.
 *
 * Both branches below compile either way - this is a plain `if`, not
 * an `#if`, so the inactive one can't bit-rot unnoticed. */
#define AV_EXPECT_COLD_BYPASS 1

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
  write(1, buf, (size_t)n);
}

static void die(const char *msg) __attribute__((noreturn));
static void die(const char *msg) {
  outmsg("QEMU_TEST: FAIL: %s: %s\n", msg, strerror(errno));
  sync();
  reboot(RB_POWER_OFF);
  _exit(1);
}

static void pass_and_poweroff(void) {
  outmsg("QEMU_TEST: PASS\n");
  sync();
  reboot(RB_POWER_OFF);
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
      reboot(RB_POWER_OFF);
      return 1;
    }
    if (!exited || code != 42) {
      outmsg("QEMU_TEST: FAIL: clean-marker exec exited unexpectedly "
             "(exited=%d code=%d)\n",
             exited, code);
      reboot(RB_POWER_OFF);
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
      reboot(RB_POWER_OFF);
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
        reboot(RB_POWER_OFF);
        return 1;
      }
    }
  }
  outmsg("QEMU_TEST: EICAR detection check passed\n");

  /* ---- Regression case: cold-pathname bypass ----
   * av/main.c's handler_pre() comment is the authoritative writeup of
   * the mechanism. cold_launcher.c is a dedicated, separate binary
   * specifically so its embedded pathname literal is guaranteed
   * genuinely untouched at exec time - see its own header comment for
   * why init.c itself can't offer that guarantee.
   *
   * Unlike the EICAR check above, this case deliberately does NOT
   * touch the pathname before exec - that touch is what makes the
   * primary check exercise the common/intended case, and skipping it
   * here is the whole point. Expectation is set by
   * AV_EXPECT_COLD_BYPASS at the top of this file. */
  {
    int killed, exited, code;

    write_file("/tmp/eicar_cold.com", EICAR);
    run_and_wait("/cold_launcher", NULL, &killed, &exited, &code);

    /* Rule out a broken test before interpreting the result either
     * way. Exactly two outcomes are meaningful: SIGKILL (av.ko caught
     * the cold exec), or cold_launcher.c's own `return 1` after its
     * inner execve() fails ENOEXEC (it ran, so the exec was not
     * blocked). Anything else - notably code 127, which is
     * run_and_wait's OWN outer execv() failing because /cold_launcher
     * is missing or non-executable in the initramfs - says nothing
     * about av/main.c and used to be reported as merely
     * "INCONCLUSIVE" while still passing the build. */
    if (!killed && !(exited && code == 1)) {
      outmsg("QEMU_TEST: FAIL: cold-pathname bypass case is broken - "
             "/cold_launcher exited unexpectedly (exited=%d code=%d, not "
             "killed). Expected either a SIGKILL or its own exit code 1; "
             "code 127 means /cold_launcher is missing or non-executable "
             "in the initramfs. This is a defect in this test, not in "
             "the av/main.c gap it tracks.\n",
             exited, code);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      reboot(RB_POWER_OFF);
      return 1;
    }

    if (AV_EXPECT_COLD_BYPASS) {
      if (killed) {
        outmsg("QEMU_TEST: FAIL: cold-pathname bypass did NOT reproduce - "
               "/cold_launcher was killed, but AV_EXPECT_COLD_BYPASS says "
               "the gap is still open. Either the gap is genuinely closed "
               "(good news: flip AV_EXPECT_COLD_BYPASS to 0 in "
               "tests/qemu-boot/init.c and update SECURITY.md and "
               "docs/evasion-findings.md to match), or this run's "
               "environment resident-faulted the pathname page for some "
               "unrelated reason. Do not silence this by relaxing the "
               "check - establish which of the two it is first; see "
               "av/main.c's handler_pre() comment and issue #2.\n");
        outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
        reboot(RB_POWER_OFF);
        return 1;
      }
      outmsg("QEMU_TEST: cold-pathname bypass reproduced as documented "
             "(exited=%d code=%d, not killed) - known open gap, asserted "
             "here so it cannot close or rot unnoticed\n",
             exited, code);
    } else {
      if (!killed) {
        outmsg("QEMU_TEST: FAIL: cold-pathname bypass REGRESSION - "
               "/cold_launcher survived a cold exec (exited=%d code=%d, "
               "not killed). AV_EXPECT_COLD_BYPASS says this gap is "
               "closed, so a surviving cold exec means the exec-time "
               "detection path regressed - see issue #2 and "
               "discussion #33.\n",
               exited, code);
        outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
        reboot(RB_POWER_OFF);
        return 1;
      }
      outmsg("QEMU_TEST: cold-pathname exec correctly blocked (killed) - "
             "gap stays closed\n");
    }
  }

  pass_and_poweroff();
  return 0; /* unreached */
}
