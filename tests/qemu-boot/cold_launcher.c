/* Dedicated regression case for the documented gap in av/main.c's
 * handler_pre()/handler_pre_execveat() (see that comment, README.md's
 * CI section, SECURITY.md, and issue #2): strncpy_from_user() in
 * atomic/kprobe context can't sleep to fault in a userspace page that
 * isn't resident yet, so a pathname argument on a genuinely cold page
 * makes the hook silently skip hashing/killing.
 *
 * This is a SEPARATE, minimal binary rather than another code path in
 * init.c on purpose: the only reliable way to guarantee a pathname
 * argument's backing page is genuinely untouched by *this process* is
 * for it to be the very first thing a freshly execve()'d image
 * references, before anything else in the program has had a chance
 * to touch nearby .rodata. init.c itself can't offer that guarantee
 * once it's already running (mounting filesystems, reading av.ko,
 * printing status, etc. all touch various pages first) - but a tiny
 * program whose entire body is "execve() a literal path, do nothing
 * else first" gets a fresh, untouched address space from the kernel's
 * own ELF loader and immediately exec's before doing anything that
 * would fault this string in as a side effect.
 *
 * An earlier version of this file passed a plain .rodata string
 * literal straight to execve() and relied on that freshness alone.
 * Measured (issue #2, kernels 6.12.107/6.18.48/7.2.2): it did NOT
 * reproduce - every run detected and killed the inner exec, most
 * likely because the launcher is small enough for fault-around to
 * pull the literal's page in alongside .text before execve() runs,
 * so the page is never actually cold. Freshness is necessary but not
 * sufficient; this version additionally guarantees coldness:
 *
 *   - The pathname bytes live in a fresh file (/tmp/cold_arg),
 *     written with write() and then mapped MAP_PRIVATE/PROT_READ.
 *     mmap() installs address space, not page tables, so the
 *     mapping starts with no resident ptes - nothing faults it
 *     before the execve() below, and fault-around only operates
 *     around pages that actually fault, so it cannot reach this
 *     VMA either. The execve() path argument (and argv[0]) point
 *     into that mapping, never at a .rodata literal.
 *   - MADV_DONTNEED on the mapping right before execve() is
 *     belt-and-braces: a no-op when (as intended) nothing has
 *     faulted the range yet, and a re-eviction if some future
 *     edit, libc startup path, or toolchain change ever touches
 *     it first. Either way the kprobe handler below sees a cold
 *     page.
 *   - Page-cache state is deliberately NOT part of this:
 *     strncpy_from_user() walks page tables without faulting, so
 *     only pte absence matters to the handler, and no
 *     fadvise()/cache-drop is needed to reproduce the -EFAULT.
 *
 * Deliberately does NOT touch the pathname first (that's init.c's
 * main test's job, demonstrating detection working for the common
 * case) - the entire point here is reproducing the cold-page bypass
 * on purpose, not avoiding it.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
  /* Written with write(), never as a C string the compiler could
   * merge, deduplicate, or place adjacent to .text - the only copy
   * that matters is the one in /tmp/cold_arg. sizeof includes the
   * NUL so the mapped page holds a proper NUL-terminated pathname. */
  static const char path_bytes[] = "/tmp/eicar_cold.com";
  long page_size = sysconf(_SC_PAGESIZE);
  int fd = open("/tmp/cold_arg", O_RDWR | O_CREAT | O_TRUNC, 0600);
  char *arg;
  char *argv[2];

  if (fd < 0)
    return 2;
  if (write(fd, path_bytes, sizeof(path_bytes)) !=
      (ssize_t)sizeof(path_bytes)) {
    close(fd);
    return 2;
  }
  /* 0600: the pathname itself is not sensitive, but there is no
   * reason to leave a world-readable staging file behind in a
   * security test's initramfs. */
  arg = mmap(NULL, (size_t)page_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (arg == MAP_FAILED)
    return 2;
  /* See the header comment: no-op when nothing has faulted this
   * range yet (the intended case), re-eviction otherwise. Either
   * way, do not touch *arg after this point before execve(). */
  madvise(arg, (size_t)page_size, MADV_DONTNEED);

  argv[0] = arg;
  argv[1] = NULL;
  execve(arg, argv, NULL);
  /* Only reached if execve itself failed (expected: eicar_cold.com is
   * plain text, not a valid ELF, so this fails ENOEXEC). If the
   * kprobe hook DID hash and flag this exec before the syscall's own
   * failure - i.e. the cold-pathname bug above is ever fixed - the
   * kill is workqueue-deferred (async) and can race against this
   * process's own exit. Same race, same fix as init.c's identical
   * usleep(1000000) after its own failed execv(): without this delay,
   * a fixed bypass could still get misreported as reproduced just
   * because this process exited before the (now-successful) kill
   * arrived. */
  usleep(1000000);
  return 1;
}
