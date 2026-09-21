/*
 * wire_escape.h - percent-encoding for tab/newline-delimited control rows.
 *
 * The avd control socket frames rows as tab-separated, newline-terminated
 * lines (see docs/avd-socket-protocol.md), but Linux filenames may legally
 * contain both '\t' and '\n'. Emitting a raw path into a row therefore
 * lets one crafted filename shift fields, inject a whole extra row, or
 * break the response shape entirely (issue #59).
 *
 * Encoding: '%' is the escape introducer. '%' itself encodes as "%25",
 * and every byte below 0x20 (covers '\t', '\n', '\r') plus 0x7F encodes
 * as "%XX" (uppercase hex). Everything else - including '/', UTF-8, and
 * non-UTF-8 high bytes - passes through literally, so ordinary paths
 * are byte-identical on the wire to before (old rows without any '%'
 * decode to themselves, which keeps this backward compatible for the
 * overwhelmingly common case).
 *
 * Decoding is deliberately total and lenient: a '%' not followed by two
 * hex digits decodes to a literal '%', so a malformed field can never
 * fail a whole listing the way a strict decoder would (that failure
 * mode is exactly the operator-visible DoS #59 describes). The one
 * accepted caveat: a pre-existing path/sidecar value containing a
 * literal "%XX" hex-looking sequence decodes to the corresponding byte.
 * Ordinary '%' (not followed by hex) round-trips untouched.
 *
 * Used by userspace/avd/avd.c (emit side + quarantine sidecar) and
 * userspace/avctl/avctl.c (display side). The GUI carries its own
 * small copy of the decode side (avd_client.unescape_field) since it
 * cannot include C headers - the two are pinned together by
 * tests/test_wire_escape.sh, which round-trips the same vectors
 * through both.
 */
#ifndef WIRE_ESCAPE_H
#define WIRE_ESCAPE_H

#include <stddef.h>

/* Worst-case expansion of wire_escape(): every input byte becomes 3
 * output bytes ("%XX"). Size escaped-field buffers as
 * WIRE_ESCAPE_MAX_EXPANSION * <unescaped bound> + 1. */
#define WIRE_ESCAPE_MAX_EXPANSION 3

/* Escapes `src` (NUL-terminated) into `dst` (capacity `dstsize`,
 * including the NUL). Returns 0 on success, -1 if the escaped form
 * does not fit (dst left NUL-terminated but truncated - callers must
 * treat -1 as "do not emit this field"). Never fails for any other
 * reason: every byte value has a defined encoding. */
static inline int wire_escape(const char *src, char *dst, size_t dstsize) {
  static const char hex[] = "0123456789ABCDEF";
  size_t di = 0;

  if (dstsize == 0)
    return -1;
  for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
    unsigned char c = *p;
    int needs_escape = (c == '%' || c < 0x20 || c == 0x7F);
    size_t need = needs_escape ? 3 : 1;
    if (di + need >= dstsize) {
      dst[di] = '\0';
      return -1;
    }
    if (needs_escape) {
      dst[di++] = '%';
      dst[di++] = hex[c >> 4];
      dst[di++] = hex[c & 0x0F];
    } else {
      dst[di++] = (char)c;
    }
  }
  dst[di] = '\0';
  return 0;
}

/* Hex value of `c`, or -1 if not a hex digit. Uppercase only on encode,
 * either case on decode (be liberal in what we accept). */
static inline int wire_hex_val(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

/* Decodes "%XX" sequences in place. The decoded form is never longer
 * than the encoded form, so in-place decoding is always safe.
 * A '%' not followed by two hex digits is kept literally (see the
 * header comment for why lenient beats strict here). */
static inline void wire_unescape(char *s) {
  char *w = s;
  for (const char *r = s; *r; r++) {
    if (*r == '%' && r[1] && r[2]) {
      int hi = wire_hex_val(r[1]);
      int lo = wire_hex_val(r[2]);
      if (hi >= 0 && lo >= 0) {
        *w++ = (char)((hi << 4) | lo);
        r += 2;
        continue;
      }
    }
    *w++ = *r;
  }
  *w = '\0';
}

#endif /* WIRE_ESCAPE_H */
