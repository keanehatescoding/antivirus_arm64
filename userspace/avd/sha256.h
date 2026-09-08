/*
 * sha256.h - minimal self-contained SHA-256 (FIPS 180-4). Used only to
 * fill in a hash for on-demand scans (avctl scan / GUI-triggered),
 * which - unlike kernel-initiated scans - have no netlink-precomputed
 * SHA-256 to reuse (see AV_A_SHA256 in av/netlink_proto.h). Deliberately
 * not linking libcrypto for this one hash - matches the project's
 * stated minimal-dependency stance (see the top-level README).
 */

#ifndef AVD_SHA256_H
#define AVD_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32

struct sha256_ctx {
  uint32_t state[8];
  uint64_t bitlen;
  unsigned char buffer[64];
  size_t buflen;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const unsigned char *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, unsigned char digest[SHA256_DIGEST_SIZE]);

/*
 * Hashes the file referenced by `fd` and writes the lowercase hex
 * digest (64 chars + NUL) into hex_out, which must be at least 65
 * bytes. Hashes through a dup()'d handle seeked to the start - same
 * convention as check_fuzzy_corpus()/check_tlsh_corpus() in avd.c.
 * Note dup() shares the open file description, so this DOES move
 * `fd`'s own read offset: EOF on success, just past max_bytes on
 * -2, indeterminate on -1. Callers must lseek() before reusing `fd`
 * (see perform_scan()'s rewind before the YARA scan).
 *
 * `max_bytes` bounds the read itself: at most max_bytes+1 bytes are
 * ever consumed, so a file that grows past the cap mid-hash (after
 * the caller's fstat() snapshot) still can't keep a scan worker busy.
 * Returns 0 on success, -1 on any I/O error, -2 if more than
 * max_bytes are readable (no digest written - a truncated prefix hash
 * would be a wrong hash presented as the file's own).
 */
int sha256_fd(int fd, char hex_out[65], size_t max_bytes);

#endif /* AVD_SHA256_H */
