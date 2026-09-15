/* Cold-pathname exec launcher for fanotify_exec_gate.c.
 *
 * Same technique as tests/qemu-boot/cold_launcher.c, and for the same
 * reason: the only way to guarantee the execve() pathname argument sits
 * on a page the kernel cannot read without faulting is to point it into
 * a fresh file-backed MAP_PRIVATE mapping that nothing has touched, in
 * a freshly execve()'d image. A .rodata literal is not enough -
 * fault-around pulls it in alongside .text (measured in issue #2).
 *
 * Differences from cold_launcher.c, both deliberate:
 *   - the target path arrives in argv rather than being hardcoded, so
 *     the harness can point it at a tmpfs it mounted at runtime. Reading
 *     argv faults argv's pages, NOT the mapping below, so the property
 *     that matters is unchanged.
 *   - this binary deliberately lives OUTSIDE the marked mount, so its
 *     own exec raises no event and the only FAN_OPEN_EXEC_PERM the
 *     spike sees for this scenario is the cold one.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
  long page_size = sysconf(_SC_PAGESIZE);
  char staging[4096];
  char *arg;
  char *child_argv[2];
  int fd;
  size_t len;

  if (argc < 3) {
    fprintf(stderr, "usage: cold_child <target-path> <staging-path>\n");
    return 2;
  }
  len = strlen(argv[1]) + 1; /* include the NUL */
  snprintf(staging, sizeof(staging), "%s", argv[2]);

  fd = open(staging, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    fprintf(stderr, "cold_child: open(%s): %m\n", staging);
    return 2;
  }
  if (write(fd, argv[1], len) != (ssize_t)len) {
    close(fd);
    return 2;
  }
  /* mmap() installs address space, not page tables: this mapping starts
   * with no resident ptes, and fault-around only works around pages
   * that actually fault, so it cannot reach this VMA either. */
  arg = mmap(NULL, (size_t)page_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (arg == MAP_FAILED) {
    fprintf(stderr, "cold_child: mmap: %m\n");
    return 2;
  }
  /* Belt and braces, exactly as in cold_launcher.c: a no-op when
   * nothing has faulted the range (the intended case), a re-eviction
   * if some future libc startup path touches it first. Do not read
   * *arg after this point. */
  madvise(arg, (size_t)page_size, MADV_DONTNEED);

  child_argv[0] = arg;
  child_argv[1] = NULL;
  execve(arg, child_argv, NULL);

  /* Only reached if the exec was refused or failed. The harness reads
   * this exit status to learn which. */
  fprintf(stderr, "cold_child: execve refused/failed: %m\n");
  return 3;
}
