/* fanotify_exec_gate.c - does FAN_OPEN_EXEC_PERM actually close the two
 * exec-time gaps tracked in issue #2?
 *
 * Discussion #33 recommends option C (a fanotify FAN_OPEN_EXEC_PERM
 * gate in avd, implemented in userspace/avd/avd.c's fanexec_* block)
 * and says both gaps die "by construction". That phrase is a
 * code-reading claim, which is the exact class of claim #34 caught
 * being wrong about cold_launcher: a fixture that could not reproduce
 * what it advertised passed quietly for weeks. So this harness tries
 * to OBSERVE the properties the redesign rests on, against a real
 * kernel, rather than trusting the reading:
 *
 *   S1  baseline/vacuity - an event is delivered at all, and FAN_ALLOW
 *       lets the exec proceed. Without this, S2-S4's "blocked" results
 *       are indistinguishable from a broken harness. This is issue
 *       #45's mandatory vacuity check, applied here.
 *   S2  FAN_DENY is a real PRE-exec refusal: the image never runs, as
 *       opposed to av_kill()'s SIGKILL landing after execve() already
 *       committed.
 *   S3  gap 1 (TOCTOU). With the exec suspended awaiting our verdict, a
 *       decoy is renamed over the target path. We then read BOTH the
 *       event fd (what fanotify hands a scanner) and a fresh open() of
 *       the pathname (what av_work_fn()'s open_exec_target() does
 *       today) and compare inode + content. The two disagreeing in one
 *       run is the gap and its fix demonstrated side by side.
 *   S4  gap 2 (cold page). The cold_launcher.c technique - execve() of
 *       a pathname on a never-faulted file-backed page - run against a
 *       fanotify listener instead of the kprobe. The same input that
 *       makes strncpy_from_user() return -EFAULT in atomic context
 *       should be a non-event here, because nothing in this decision
 *       path copies a pathname from userspace at all.
 *
 * This deliberately exercises the MECHANISM with the same flags and
 * call sequence avd's gate uses (FAN_CLASS_CONTENT, FAN_MARK_MOUNT,
 * FAN_OPEN_EXEC_PERM, respond-then-close), not avd itself: avd refuses
 * to start without the av kernel module, which is arm64-only, so the
 * integrated path cannot run on a normal development host. See
 * tests/test_fanotify_exec_gate.sh's header for what that does and
 * does not cover.
 *
 * Blast radius: this mounts its OWN tmpfs and marks that mount, so
 * FAN_MARK_MOUNT cannot suspend execs anywhere else on the machine,
 * and a hard alarm() guarantees the listener can never sit on a
 * pending permission event indefinitely. Needs CAP_SYS_ADMIN
 * (fanotify permission classes) - the wrapper script elevates via
 * pkexec, matching tests/run_all.sh.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKDIR "/tmp/av-fanotify-gate-test"
#define MAL_MARKER "SPIKE-PAYLOAD-MALICIOUS"
#define CLEAN_MARKER "SPIKE-PAYLOAD-DECOY-CLEAN"
#define EVENT_TIMEOUT_MS 5000
#define HARD_TIMEOUT_SECS 60

static int failures;
static int mounted;
static const char *cold_child_path;

static void note(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  putchar('\n');
  fflush(stdout);
}

static void check(bool ok, const char *what) {
  note("    [%s] %s", ok ? "PASS" : "FAIL", what);
  if (!ok)
    failures++;
}

static void cleanup(void) {
  if (mounted) {
    /* MNT_DETACH so a still-running child cannot make this fail and
     * leave a marked tmpfs behind. */
    if (umount2(WORKDIR, MNT_DETACH) != 0)
      note("fanotify-gate: warning: umount %s: %s", WORKDIR, strerror(errno));
    mounted = 0;
  }
  rmdir(WORKDIR);
}

static void on_alarm(int sig) {
  (void)sig;
  /* Deliberately crude: if we ever hang holding a permission event, the
   * safest thing is to die, which makes the kernel release every
   * pending event (allowing it) rather than wedging execs on our tmpfs. */
  const char msg[] = "fanotify-gate: HARD TIMEOUT - aborting so pending execs are released\n";
  ssize_t ignored = write(STDERR_FILENO, msg, sizeof(msg) - 1);
  (void)ignored;
  umount2(WORKDIR, MNT_DETACH);
  _exit(70);
}

/* ------------------------------------------------------------------ */

struct ident {
  dev_t dev;
  ino_t ino;
};

static bool ident_of_fd(int fd, struct ident *out) {
  struct stat st;
  if (fstat(fd, &st) != 0)
    return false;
  out->dev = st.st_dev;
  out->ino = st.st_ino;
  return true;
}

static bool ident_of_path(const char *path, struct ident *out) {
  struct stat st;
  if (stat(path, &st) != 0)
    return false;
  out->dev = st.st_dev;
  out->ino = st.st_ino;
  return true;
}

static bool ident_eq(const struct ident *a, const struct ident *b) {
  return a->dev == b->dev && a->ino == b->ino;
}

/* Which staged marker, if any, does this fd's content carry? Reads from
 * offset 0 explicitly (pread) because the event fd's offset is not ours
 * to assume. */
static const char *marker_of_fd(int fd) {
  static char buf[1 << 20];
  ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
  if (n < 0)
    return "<read failed>";
  buf[n] = '\0';
  if (memmem(buf, (size_t)n, MAL_MARKER, strlen(MAL_MARKER)))
    return MAL_MARKER;
  if (memmem(buf, (size_t)n, CLEAN_MARKER, strlen(CLEAN_MARKER)))
    return CLEAN_MARKER;
  return "<no marker>";
}

static const char *marker_of_path(const char *path) {
  const char *m;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return "<open failed>";
  m = marker_of_fd(fd);
  close(fd);
  return m;
}

/* Copy an existing ELF and append a distinguishing marker. Appending
 * trailing bytes to an ELF is ignored by the loader, so the copy still
 * executes - we get two byte-different, separately-identifiable but
 * equally runnable payloads. */
static bool stage_payload(const char *src, const char *dst,
                          const char *marker) {
  char buf[65536];
  ssize_t n;
  int in = open(src, O_RDONLY | O_CLOEXEC);
  int out;
  if (in < 0) {
    note("fanotify-gate: open(%s): %s", src, strerror(errno));
    return false;
  }
  out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (out < 0) {
    note("fanotify-gate: open(%s): %s", dst, strerror(errno));
    close(in);
    return false;
  }
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    if (write(out, buf, (size_t)n) != n) {
      close(in);
      close(out);
      return false;
    }
  }
  close(in);
  if (write(out, marker, strlen(marker)) != (ssize_t)strlen(marker)) {
    close(out);
    return false;
  }
  close(out);
  return true;
}

/* ------------------------------------------------------------------ */

static void respond(int fan_fd, int event_fd, __u32 decision) {
  struct fanotify_response resp;
  memset(&resp, 0, sizeof(resp));
  resp.fd = event_fd;
  resp.response = decision;
  if (write(fan_fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp))
    note("fanotify-gate: writing fanotify response: %s", strerror(errno));
}

/* Pull events until one names `want` (or, when want is NULL, until any
 * event arrives). Anything else is allowed through untouched, which is
 * what lets scenario 4's own launcher run. Returns the matching event's
 * fd (caller owns it and MUST respond), or -1 on timeout. */
static int await_event_for(int fan_fd, const struct ident *want,
                           uint32_t *pid_out) {
  static char buf[8192];

  for (;;) {
    struct fanotify_event_metadata *md;
    struct pollfd pfd = {.fd = fan_fd, .events = POLLIN};
    ssize_t len;
    int pret = poll(&pfd, 1, EVENT_TIMEOUT_MS);

    if (pret == 0) {
      note("fanotify-gate: timed out waiting for a FAN_OPEN_EXEC_PERM event");
      return -1;
    }
    if (pret < 0) {
      if (errno == EINTR)
        continue;
      note("fanotify-gate: poll: %s", strerror(errno));
      return -1;
    }

    len = read(fan_fd, buf, sizeof(buf));
    if (len <= 0) {
      note("fanotify-gate: read(fanotify): %s", strerror(errno));
      return -1;
    }

    for (md = (struct fanotify_event_metadata *)buf;
         FAN_EVENT_OK(md, len); md = FAN_EVENT_NEXT(md, len)) {
      struct ident got;

      if (md->vers != FANOTIFY_METADATA_VERSION) {
        note("fanotify-gate: fanotify ABI mismatch (got v%u, built against v%u)",
             md->vers, FANOTIFY_METADATA_VERSION);
        return -1;
      }
      if (md->fd == FAN_NOFD) {
        /* FAN_Q_OVERFLOW - one of the fail-open surfaces #33 flags as
         * needing a policy. Worth seeing if it ever shows up here. */
        note("fanotify-gate: FAN_Q_OVERFLOW (queue overflow, events were dropped)");
        continue;
      }
      if (!(md->mask & FAN_OPEN_EXEC_PERM)) {
        respond(fan_fd, md->fd, FAN_ALLOW);
        close(md->fd);
        continue;
      }
      if (!ident_of_fd(md->fd, &got)) {
        respond(fan_fd, md->fd, FAN_ALLOW);
        close(md->fd);
        continue;
      }
      if (want && !ident_eq(&got, want)) {
        /* Not the file under test - let it run. */
        respond(fan_fd, md->fd, FAN_ALLOW);
        close(md->fd);
        continue;
      }
      if (pid_out)
        *pid_out = (uint32_t)md->pid;
      return md->fd;
    }
  }
}

static const char *status_str(int status) {
  static char buf[128];
  if (status < 0)
    return "<fork/wait failed>";
  if (WIFSIGNALED(status)) {
    snprintf(buf, sizeof(buf), "killed by signal %d", WTERMSIG(status));
    return buf;
  }
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code >= 100)
      snprintf(buf, sizeof(buf), "exec refused, errno=%d (%s)", code - 100,
               strerror(code - 100));
    else
      snprintf(buf, sizeof(buf), "ran, exit code %d", code);
    return buf;
  }
  snprintf(buf, sizeof(buf), "status 0x%x", status);
  return buf;
}

/* ------------------------------------------------------------------ */

static void s1_baseline(int fan_fd) {
  const char *path = WORKDIR "/clean.elf";
  struct ident want;
  int event_fd, status;
  uint32_t pid = 0;
  pid_t child;

  note("\nS1  baseline / vacuity check - is anything delivered at all?");
  if (!stage_payload("/bin/true", path, CLEAN_MARKER) ||
      !ident_of_path(path, &want)) {
    check(false, "staged a clean payload");
    return;
  }
  note("    staged %s (ino=%llu)", path, (unsigned long long)want.ino);

  child = fork();
  if (child == 0) {
    char *const argv[] = {(char *)path, NULL};
    execv(path, argv);
    _exit(100 + (errno & 0x7f));
  }

  event_fd = await_event_for(fan_fd, &want, &pid);
  check(event_fd >= 0, "FAN_OPEN_EXEC_PERM event delivered for the exec");
  if (event_fd < 0) {
    waitpid(child, NULL, 0);
    return;
  }
  note("    event: pid=%u fd=%d", pid, event_fd);
  respond(fan_fd, event_fd, FAN_ALLOW);
  close(event_fd);

  waitpid(child, &status, 0);
  note("    child: %s", status_str(status));
  check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "FAN_ALLOW let the exec proceed (so a block below means something)");
}

static void s2_deny_is_pre_exec(int fan_fd) {
  const char *path = WORKDIR "/mal.elf";
  struct ident want;
  int event_fd, status;
  pid_t child;

  note("\nS2  is FAN_DENY a real PRE-exec refusal?");
  if (!stage_payload("/bin/true", path, MAL_MARKER) ||
      !ident_of_path(path, &want)) {
    check(false, "staged a malicious payload");
    return;
  }

  child = fork();
  if (child == 0) {
    char *const argv[] = {(char *)path, NULL};
    execv(path, argv);
    _exit(100 + (errno & 0x7f));
  }

  event_fd = await_event_for(fan_fd, &want, NULL);
  if (event_fd < 0) {
    check(false, "event delivered");
    waitpid(child, NULL, 0);
    return;
  }
  respond(fan_fd, event_fd, FAN_DENY);
  close(event_fd);

  waitpid(child, &status, 0);
  note("    child: %s", status_str(status));
  check(WIFEXITED(status) && WEXITSTATUS(status) >= 100,
        "the image never ran - refused at exec time, not SIGKILLed after");
}

static void s3_toctou(int fan_fd) {
  const char *target = WORKDIR "/target.elf";
  const char *decoy = WORKDIR "/decoy.elf";
  struct ident want, decoy_id;
  /* Zeroed, and the ident_of_* results are checked below: a failed
   * fstat()/stat() must not silently turn into a comparison against
   * stack garbage - in a harness whose whole output is evidence, a
   * bogus PASS is worse than a loud failure. */
  struct ident from_fd = {0}, from_path = {0};
  bool have_fd_id, have_path_id;
  const char *marker_fd, *marker_path;
  int event_fd, status;
  pid_t child;

  note("\nS3  gap 1 (TOCTOU): can a rename swap the file out from under the verdict?");
  if (!stage_payload("/bin/true", target, MAL_MARKER) ||
      !stage_payload("/bin/true", decoy, CLEAN_MARKER) ||
      !ident_of_path(target, &want) || !ident_of_path(decoy, &decoy_id)) {
    check(false, "staged target + decoy");
    return;
  }
  note("    target ino=%llu (%s), decoy ino=%llu (%s)",
       (unsigned long long)want.ino, MAL_MARKER,
       (unsigned long long)decoy_id.ino, CLEAN_MARKER);

  child = fork();
  if (child == 0) {
    char *const argv[] = {(char *)target, NULL};
    execv(target, argv);
    _exit(100 + (errno & 0x7f));
  }

  event_fd = await_event_for(fan_fd, &want, NULL);
  if (event_fd < 0) {
    check(false, "event delivered");
    waitpid(child, NULL, 0);
    return;
  }

  /* The exec is now suspended awaiting our verdict. This is the window
   * av_work_fn() runs in - except it re-opens by pathname, and we hold
   * the kernel's own fd. Swap the decoy in and ask both. */
  if (rename(decoy, target) != 0) {
    note("    rename(decoy -> target): %s", strerror(errno));
    check(false, "swapped the decoy over the target path");
    respond(fan_fd, event_fd, FAN_ALLOW);
    close(event_fd);
    waitpid(child, NULL, 0);
    return;
  }
  note("    swapped: %s now resolves to the decoy inode", target);

  have_fd_id = ident_of_fd(event_fd, &from_fd);
  marker_fd = marker_of_fd(event_fd);
  have_path_id = ident_of_path(target, &from_path);
  marker_path = marker_of_path(target);
  check(have_fd_id && have_path_id,
        "could identify both the event fd and the re-opened path");

  note("    via the event fd   : ino=%llu content=%s   <- fanotify (option C)",
       (unsigned long long)from_fd.ino, marker_fd);
  note("    via re-opening path: ino=%llu content=%s   <- open_exec_target() today",
       (unsigned long long)from_path.ino, marker_path);

  check(have_fd_id && ident_eq(&from_fd, &want) &&
            strcmp(marker_fd, MAL_MARKER) == 0,
        "the event fd still names the inode that is actually executing");
  check(have_path_id && ident_eq(&from_path, &decoy_id) &&
            strcmp(marker_path, CLEAN_MARKER) == 0,
        "re-opening the path sees the decoy (the #2 gap, reproduced)");
  check(have_fd_id && have_path_id && !ident_eq(&from_fd, &from_path),
        "the two disagree: verdict-from-fd and verdict-from-path differ");

  /* Verdict computed from the fd says malicious, so deny. */
  respond(fan_fd, event_fd, FAN_DENY);
  close(event_fd);

  waitpid(child, &status, 0);
  note("    child: %s", status_str(status));
  check(WIFEXITED(status) && WEXITSTATUS(status) >= 100,
        "the fd-derived verdict is what got enforced - swap did not help");
}

static void s4_cold_pathname(int fan_fd) {
  const char *target = WORKDIR "/cold_target.elf";
  const char *staging = "/tmp/av-fanotify-gate-test-coldarg";
  struct ident want;
  int event_fd, status;
  uint32_t pid = 0;
  pid_t child;

  note("\nS4  gap 2 (cold page): the cold_launcher technique vs a fanotify listener");
  if (!stage_payload("/bin/true", target, MAL_MARKER) ||
      !ident_of_path(target, &want)) {
    check(false, "staged the cold-exec target");
    return;
  }
  note("    target ino=%llu, pathname will live on a never-faulted mapping",
       (unsigned long long)want.ino);

  child = fork();
  if (child == 0) {
    char *const argv[] = {(char *)cold_child_path, (char *)target,
                          (char *)staging, NULL};
    execv(cold_child_path, argv);
    _exit(100 + (errno & 0x7f));
  }

  event_fd = await_event_for(fan_fd, &want, &pid);
  check(event_fd >= 0,
        "event still delivered for an exec whose pathname page is cold");
  if (event_fd < 0) {
    waitpid(child, NULL, 0);
    unlink(staging);
    return;
  }
  {
    struct ident got = {0};
    bool have_id = ident_of_fd(event_fd, &got);
    note("    event: pid=%u ino=%llu content=%s", pid,
         (unsigned long long)got.ino, marker_of_fd(event_fd));
    check(have_id && ident_eq(&got, &want),
          "the fd names the right inode - no pathname copy was involved");
  }
  respond(fan_fd, event_fd, FAN_DENY);
  close(event_fd);

  waitpid(child, &status, 0);
  note("    child: %s", status_str(status));
  check(WIFEXITED(status) && WEXITSTATUS(status) != 0,
        "the cold exec was blocked (kprobe path fails open here - see #2)");
  unlink(staging);
}

/* ------------------------------------------------------------------ */

/* Does this errno mean "this kernel does not support the feature" as
 * opposed to "the call failed for a reason that matters"? Callers use
 * it to pick exit code 78 (loud skip) over 1 (failure). */
static int kernel_cannot(int e) {
  return e == EINVAL || e == EOPNOTSUPP || e == ENOSYS;
}

int main(int argc, char **argv) {
  int fan_fd;
  struct sigaction sa;

  if (argc > 1)
    cold_child_path = argv[1];
  else
    cold_child_path = "./cold_child";

  if (geteuid() != 0) {
    note("fanotify-gate: needs root (fanotify permission events require CAP_SYS_ADMIN)");
    return 77;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_alarm;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM, &sa, NULL);
  alarm(HARD_TIMEOUT_SECS);

  {
    struct utsname u;
    if (uname(&u) == 0)
      note("fanotify-gate: kernel %s %s", u.release, u.machine);
  }

  /* Own tmpfs, so FAN_MARK_MOUNT below cannot suspend an exec anywhere
   * else on this machine. */
  if (mkdir(WORKDIR, 0755) != 0 && errno != EEXIST) {
    note("fanotify-gate: mkdir(%s): %s", WORKDIR, strerror(errno));
    return 1;
  }
  if (mount("tmpfs", WORKDIR, "tmpfs", 0, "mode=0755,size=64m") != 0) {
    note("fanotify-gate: mount tmpfs on %s: %s", WORKDIR, strerror(errno));
    rmdir(WORKDIR);
    return 1;
  }
  mounted = 1;
  note("fanotify-gate: mounted a private tmpfs at %s (blast radius = this mount)",
       WORKDIR);

  /* NB: there is no FAN_CLASS_PERM, despite #33's option C writeup
   * naming one. Permission events require FAN_CLASS_CONTENT (or
   * FAN_CLASS_PRE_CONTENT); FAN_CLASS_NOTIF can only observe. */
  fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
                         O_RDONLY | O_LARGEFILE | O_CLOEXEC);
  if (fan_fd < 0) {
    int e = errno;
    note("fanotify-gate: fanotify_init(FAN_CLASS_CONTENT): %s", strerror(e));
    note("fanotify-gate: (needs CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y + CAP_SYS_ADMIN)");
    cleanup();
    /* "this kernel cannot do permission events" and "the gate is
     * broken" are different answers and must not share an exit code:
     * the first is a loud skip, the second is a failure. A kernel
     * built without CONFIG_FANOTIFY_ACCESS_PERMISSIONS rejects the
     * permission-capable classes with EINVAL; anything else here
     * (EMFILE, ENOMEM, ...) is a real problem with this run. */
    return kernel_cannot(e) ? 78 : 1;
  }
  if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                    FAN_OPEN_EXEC_PERM, AT_FDCWD, WORKDIR) != 0) {
    int e = errno;
    note("fanotify-gate: fanotify_mark(FAN_OPEN_EXEC_PERM): %s", strerror(e));
    note("fanotify-gate: (FAN_OPEN_EXEC_PERM needs kernel >= 5.0)");
    close(fan_fd);
    cleanup();
    /* Same split as above: a pre-5.0 kernel does not know this event
     * bit and says EINVAL - a skip, not a failed assertion. */
    return kernel_cannot(e) ? 78 : 1;
  }
  note("fanotify-gate: marked %s for FAN_OPEN_EXEC_PERM", WORKDIR);

  s1_baseline(fan_fd);
  s2_deny_is_pre_exec(fan_fd);
  s3_toctou(fan_fd);
  s4_cold_pathname(fan_fd);

  close(fan_fd);
  cleanup();

  note("\n=== %s: %d check(s) failed ===", failures ? "FAIL" : "PASS",
       failures);
  return failures ? 1 : 0;
}
