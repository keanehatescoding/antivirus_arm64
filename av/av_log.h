/*
 * av_log.h - structured-dmesg string escaping (CWE-117 log forging).
 *
 * Every kernel-av log line is a single structured key=value record
 * (event=... type=... path="..." ...). Pathname bytes come from the
 * exec/open/unlink target and may contain quotes, backslashes, or
 * control characters (including '\n') via a crafted filename. Emitting
 * them raw inside path="..." lets one exec forge extra fields or whole
 * log lines. Escape pathname-class strings with av_escape_log_str()
 * before logging; the recorded identities (behavior table, netlink
 * messages to the daemon) keep the raw bytes - only the dmesg rendering
 * is escaped, so comparisons and daemon-side matching are unaffected.
 * Ordinary printable paths pass through byte-identical, so existing
 * dmesg greps (e.g. tests/test_detection.sh matching path="/bin/ls")
 * keep matching.
 */

#ifndef AV_LOG_H
#define AV_LOG_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h> /* userspace test harness only - lets the exact byte
                     * mapping below run under a plain userspace gcc */
#endif

/* Escape src into dst for use inside a quoted dmesg field: '\\' -> "\\\\",
 * '"' -> "\\\"", every byte outside printable ASCII (0x20-0x7e) ->
 * "\xNN" (lowercase hex). Always NUL-terminates (unless dst_len == 0);
 * stops before emitting a unit that would not fit, so the output is
 * never a truncated escape sequence - hostile names may be cut short
 * but can never break out of the quoted field. Returns dst.
 * Non-ASCII (UTF-8) bytes are escaped too: dmesg is byte-oriented and
 * the structured format stays greppable this way. Pure C, no kernel
 * helpers, so the exact byte mapping is reviewable here and testable
 * in userspace (throwaway harness, not committed). */
static inline char *av_escape_log_str(const char *src, char *dst,
                                      size_t dst_len)
{
  static const char hex[] = "0123456789abcdef";
  size_t di = 0;

  if (dst_len == 0)
    return dst;
  while (*src) {
    unsigned char c = (unsigned char)*src++;
    if (c == '\\' || c == '"') {
      if (di + 2 >= dst_len)
        break;
      dst[di++] = '\\';
      dst[di++] = (char)c;
    } else if (c >= 0x20 && c <= 0x7e) {
      if (di + 1 >= dst_len)
        break;
      dst[di++] = (char)c;
    } else {
      if (di + 4 >= dst_len)
        break;
      dst[di++] = '\\';
      dst[di++] = 'x';
      dst[di++] = hex[(c >> 4) & 0xf];
      dst[di++] = hex[c & 0xf];
    }
  }
  dst[di] = '\0';
  return dst;
}

#endif /* AV_LOG_H */
