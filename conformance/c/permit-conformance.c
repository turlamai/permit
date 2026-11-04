/*
 * Permit Protocol v1 conformance runner (C).
 *
 * A non-Racket implementation that exercises the portable vector corpus in
 * test-vectors/v1/. It authenticates the exact decoded payload bytes with
 * Ed25519, applies the trust-store rules, validates closed claim schemas,
 * and evaluates the checked-in positive and negative policy cases. Passing
 * this runner is the cross-language evidence referenced by ROADMAP.md and
 * docs/compatibility.md.
 *
 * The runner mirrors the Racket reference implementation exactly:
 *
 *   - strict JSON with recursive duplicate-member rejection and a depth
 *     limit of 64, over the envelope, the trust store, and the payload;
 *   - canonical padded standard Base64 for envelope fields;
 *   - Ed25519 over the exact payload bytes, verified before the payload is
 *     parsed and before the issuer, issuance window, or key purpose are
 *     consulted;
 *   - canonical RFC 3339 UTC timestamps that compare chronologically as
 *     strings; inclusive window boundaries everywhere;
 *   - SemVer 2.0 precedence for version_policy;
 *   - fail-closed policy when required product metadata is missing.
 *
 * Requires OpenSSL 3.x (libcrypto). The corpus directory is passed as the
 * single argument:
 *
 *     ./permit-conformance ../../test-vectors/v1
 *
 * Exit status is zero only when every check passes.
 */

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

static char g_error[512];

static void set_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(g_error, sizeof(g_error), fmt, args);
  va_end(args);
}

static void *xmalloc(size_t size) {
  void *p = malloc(size ? size : 1);
  if (!p) {
    fprintf(stderr, "out of memory\n");
    exit(2);
  }
  return p;
}

static void *xrealloc(void *old, size_t size) {
  void *p = realloc(old, size ? size : 1);
  if (!p) {
    fprintf(stderr, "out of memory\n");
    exit(2);
  }
  return p;
}

static char *xstrdup(const char *s) {
  size_t n = strlen(s);
  char *copy = xmalloc(n + 1);
  memcpy(copy, s, n + 1);
  return copy;
}

static int str_equals(const char *a, const char *b) {
  return a && b && strcmp(a, b) == 0;
}

typedef struct {
  unsigned char *data;
  size_t len;
} Bytes;

static void bytes_free(Bytes *b) {
  free(b->data);
  b->data = NULL;
  b->len = 0;
}

static Bytes read_whole_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    set_error("cannot open %s", path);
    Bytes empty = {NULL, 0};
    return empty;
  }
  size_t cap = 4096, len = 0;
  unsigned char *buf = xmalloc(cap);
  for (;;) {
    if (len == cap) {
      cap *= 2;
      buf = xrealloc(buf, cap);
    }
    size_t got = fread(buf + len, 1, cap - len, f);
    len += got;
    if (got == 0) break;
  }
  int bad = ferror(f);
  fclose(f);
  if (bad) {
    free(buf);
    set_error("cannot read %s", path);
    Bytes empty = {NULL, 0};
    return empty;
  }
  Bytes b;
  b.data = buf;
  b.len = len;
  return b;
}

/* ------------------------------------------------------------------ */
/* Base64: strict canonical, padded, standard alphabet                 */
/* ------------------------------------------------------------------ */

static int b64_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

static void b64_encode(const unsigned char *in, size_t len, char *out) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0;
  for (size_t i = 0; i + 2 < len; i += 3) {
    unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
    out[o++] = alphabet[(v >> 18) & 63];
    out[o++] = alphabet[(v >> 12) & 63];
    out[o++] = alphabet[(v >> 6) & 63];
    out[o++] = alphabet[v & 63];
  }
  size_t rem = len % 3;
  if (rem == 1) {
    unsigned v = (unsigned)in[len - 1] << 16;
    out[o++] = alphabet[(v >> 18) & 63];
    out[o++] = alphabet[(v >> 12) & 63];
    out[o++] = '=';
    out[o++] = '=';
  } else if (rem == 2) {
    unsigned v = ((unsigned)in[len - 2] << 16) | ((unsigned)in[len - 1] << 8);
    out[o++] = alphabet[(v >> 18) & 63];
    out[o++] = alphabet[(v >> 12) & 63];
    out[o++] = alphabet[(v >> 6) & 63];
    out[o++] = '=';
  }
  out[o] = '\0';
}

/* Returns 0 on success; -1 invalid spelling, -2 non-canonical. */
static int b64_decode(const char *in, size_t in_len, Bytes *out) {
  if (in_len % 4 != 0) return -1;
  size_t pad = 0;
  while (pad < in_len && pad < 2 && in[in_len - 1 - pad] == '=') pad++;
  for (size_t i = 0; i < in_len; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == '=') {
      if (i < in_len - pad) return -1; /* '=' only in the final group */
    } else if (b64_value(c) < 0) {
      return -1;
    }
  }
  /* A group may not encode to more than two padding characters. */
  if (pad == 2 && in_len >= 4) {
    size_t g = in_len - 4;
    if (in[g] == '=') return -1;
  }
  size_t out_len = in_len / 4 * 3;
  if (pad == 1) out_len -= 1;
  if (pad == 2) out_len -= 2;
  unsigned char *decoded = xmalloc(out_len ? out_len : 1);
  size_t o = 0;
  for (size_t i = 0; i < in_len; i += 4) {
    int v[4];
    for (int k = 0; k < 4; k++) {
      v[k] = in[i + k] == '=' ? 0 : b64_value((unsigned char)in[i + k]);
    }
    unsigned n = ((unsigned)v[0] << 18) | ((unsigned)v[1] << 12) |
                 ((unsigned)v[2] << 6) | (unsigned)v[3];
    if (o < out_len) decoded[o++] = (unsigned char)(n >> 16);
    if (o < out_len) decoded[o++] = (unsigned char)(n >> 8);
    if (o < out_len) decoded[o++] = (unsigned char)n;
  }
  char *reencoded = xmalloc(in_len + 1);
  b64_encode(decoded, out_len, reencoded);
  int canonical = strncmp(reencoded, in, in_len) == 0 && reencoded[in_len] == '\0' &&
                  strlen(in) == in_len;
  free(reencoded);
  if (!canonical) {
    free(decoded);
    return -2;
  }
  out->data = decoded;
  out->len = out_len;
  return 0;
}

/* ------------------------------------------------------------------ */
/* SHA-256 and Ed25519 over exact bytes (OpenSSL)                      */
/* ------------------------------------------------------------------ */

static void sha256_hex(const unsigned char *data, size_t len, char hex[65]) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  if (!EVP_Digest(data, len, digest, &digest_len, EVP_sha256(), NULL)) {
    fprintf(stderr, "SHA-256 failure\n");
    exit(2);
  }
  static const char digits[] = "0123456789abcdef";
  for (unsigned int i = 0; i < digest_len; i++) {
    hex[i * 2] = digits[digest[i] >> 4];
    hex[i * 2 + 1] = digits[digest[i] & 15];
  }
  hex[64] = '\0';
}

/* Decodes a base64 DER SubjectPublicKeyInfo into the 32 raw key bytes. */
static int ed25519_raw_from_spki(const unsigned char *der, size_t der_len,
                                 unsigned char raw[32]) {
  const unsigned char *cursor = der;
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &cursor, (long)der_len);
  if (!pkey) return 0;
  if ((size_t)(cursor - der) != der_len) {
    EVP_PKEY_free(pkey);
    return 0;
  }
  size_t len = 32;
  int ok = EVP_PKEY_get_raw_public_key(pkey, raw, &len) == 1 && len == 32;
  EVP_PKEY_free(pkey);
  return ok;
}

static int ed25519_verify(const unsigned char raw_key[32],
                          const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig, size_t sig_len) {
  if (sig_len != 64) return 0;
  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw_key, 32);
  if (!pkey) return 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return 0;
  }
  int ok = 0;
  if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1) {
    ok = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1;
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

/* ------------------------------------------------------------------ */
/* Strict JSON: recursive duplicate-member rejection, depth limit 64   */
/* ------------------------------------------------------------------ */

#define JSON_MAX_DEPTH 64

typedef enum { J_NULL, J_BOOL, J_INT, J_REAL, J_STRING, J_ARRAY, J_OBJECT } JsonKind;

typedef struct Json Json;
struct Json {
  JsonKind kind;
  int boolean;          /* J_BOOL */
  long long integer;    /* J_INT */
  double real;          /* J_REAL */
  char *str;            /* J_STRING (decoded UTF-8, NUL-terminated) */
  size_t str_len;       /* J_STRING length excluding the terminator */
  Json **items;         /* J_ARRAY */
  size_t n;             /* J_ARRAY / J_OBJECT member count */
  char **keys;          /* J_OBJECT */
  Json **values;        /* J_OBJECT */
};

static void json_free(Json *v) {
  if (!v) return;
  free(v->str);
  for (size_t i = 0; i < v->n; i++) {
    if (v->items) json_free(v->items[i]);
    if (v->keys) {
      free(v->keys[i]);
      json_free(v->values[i]);
    }
  }
  free(v->items);
  free(v->keys);
  free(v->values);
  free(v);
}

typedef struct {
  const char *buf;
  size_t len;
  size_t pos;
  int depth;
  int failed;
} JsonParser;

static void json_fail(JsonParser *p, const char *fmt, ...) {
  if (p->failed) return;
  va_list args;
  va_start(args, fmt);
  char detail[256];
  vsnprintf(detail, sizeof(detail), fmt, args);
  va_end(args);
  set_error("invalid JSON at offset %zu: %s", p->pos, detail);
  p->failed = 1;
}

static int json_at_end(JsonParser *p) {
  return p->pos >= p->len;
}

static char json_peek(JsonParser *p) {
  return p->pos < p->len ? p->buf[p->pos] : '\0';
}

static void json_skip_ws(JsonParser *p) {
  while (p->pos < p->len) {
    char c = p->buf[p->pos];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      p->pos++;
    } else {
      break;
    }
  }
}

/* Validates UTF-8 over the whole document; rejects overlong encodings,
 * surrogates, and anything above U+10FFFF. */
static int utf8_valid(const char *buf, size_t len) {
  size_t i = 0;
  while (i < len) {
    unsigned char c = (unsigned char)buf[i];
    size_t need;
    long code_min;
    unsigned long cp;
    if (c < 0x80) {
      i++;
      continue;
    } else if ((c & 0xE0) == 0xC0) {
      need = 1;
      code_min = 0x80;
      cp = c & 0x1F;
    } else if ((c & 0xF0) == 0xE0) {
      need = 2;
      code_min = 0x800;
      cp = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
      need = 3;
      code_min = 0x10000;
      cp = c & 0x07;
    } else {
      return 0;
    }
    if (len - i - 1 < need) return 0;
    for (size_t k = 1; k <= need; k++) {
      unsigned char cc = (unsigned char)buf[i + k];
      if ((cc & 0xC0) != 0x80) return 0;
      cp = (cp << 6) | (cc & 0x3F);
    }
    if ((long)cp < code_min || cp > 0x10FFFF) return 0;
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
    i += need + 1;
  }
  return 0 == 0;
}

static void utf8_push(char **out, size_t *len, size_t *cap, unsigned long cp) {
  char encoded[4];
  size_t n;
  if (cp < 0x80) {
    encoded[0] = (char)cp;
    n = 1;
  } else if (cp < 0x800) {
    encoded[0] = (char)(0xC0 | (cp >> 6));
    encoded[1] = (char)(0x80 | (cp & 0x3F));
    n = 2;
  } else if (cp < 0x10000) {
    encoded[0] = (char)(0xE0 | (cp >> 12));
    encoded[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    encoded[2] = (char)(0x80 | (cp & 0x3F));
    n = 3;
  } else {
    encoded[0] = (char)(0xF0 | (cp >> 18));
    encoded[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    encoded[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    encoded[3] = (char)(0x80 | (cp & 0x3F));
    n = 4;
  }
  if (*len + n > *cap) {
    while (*len + n > *cap) *cap = *cap ? *cap * 2 : 16;
    *out = xrealloc(*out, *cap);
  }
  memcpy(*out + *len, encoded, n);
  *len += n;
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Parses a JSON string starting at the opening quote. */
static char *json_parse_string_raw(JsonParser *p, size_t *out_len) {
  if (json_peek(p) != '"') {
    json_fail(p, "expected JSON string");
    return NULL;
  }
  p->pos++;
  char *decoded = NULL;
  size_t len = 0, cap = 0;
  for (;;) {
    if (json_at_end(p)) {
      json_fail(p, "unterminated JSON string");
      goto fail;
    }
    unsigned char c = (unsigned char)p->buf[p->pos];
    if (c == '"') {
      p->pos++;
      if (!decoded) decoded = xmalloc(1);
      if (len + 1 > cap) {
        cap = len + 1;
        decoded = xrealloc(decoded, cap);
      }
      decoded[len] = '\0';
      *out_len = len;
      return decoded;
    }
    if (c < 0x20) {
      json_fail(p, "raw control character inside JSON string");
      goto fail;
    }
    if (c == '\\') {
      p->pos++;
      if (json_at_end(p)) {
        json_fail(p, "unterminated JSON escape");
        goto fail;
      }
      char e = p->buf[p->pos++];
      switch (e) {
        case '"': utf8_push(&decoded, &len, &cap, '"'); break;
        case '\\': utf8_push(&decoded, &len, &cap, '\\'); break;
        case '/': utf8_push(&decoded, &len, &cap, '/'); break;
        case 'b': utf8_push(&decoded, &len, &cap, '\b'); break;
        case 'f': utf8_push(&decoded, &len, &cap, '\f'); break;
        case 'n': utf8_push(&decoded, &len, &cap, '\n'); break;
        case 'r': utf8_push(&decoded, &len, &cap, '\r'); break;
        case 't': utf8_push(&decoded, &len, &cap, '\t'); break;
        case 'u': {
          if (p->pos + 4 > p->len) {
            json_fail(p, "truncated \\u escape");
            goto fail;
          }
          unsigned long cp = 0;
          for (int k = 0; k < 4; k++) {
            int h = hex_value(p->buf[p->pos + k]);
            if (h < 0) {
              json_fail(p, "invalid \\u escape");
              goto fail;
            }
            cp = (cp << 4) | (unsigned long)h;
          }
          if (cp == 0) {
            json_fail(p, "NUL escape in JSON string");
            goto fail;
          }
          p->pos += 4;
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (p->pos + 6 > p->len || p->buf[p->pos] != '\\' ||
                p->buf[p->pos + 1] != 'u') {
              json_fail(p, "unpaired surrogate in \\u escape");
              goto fail;
            }
            unsigned long low = 0;
            for (int k = 0; k < 4; k++) {
              int h = hex_value(p->buf[p->pos + 2 + k]);
              if (h < 0) {
                json_fail(p, "invalid \\u escape");
                goto fail;
              }
              low = (low << 4) | (unsigned long)h;
            }
            if (low < 0xDC00 || low > 0xDFFF) {
              json_fail(p, "unpaired surrogate in \\u escape");
              goto fail;
            }
            p->pos += 6;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            json_fail(p, "unpaired surrogate in \\u escape");
            goto fail;
          }
          utf8_push(&decoded, &len, &cap, cp);
          break;
        }
        default:
          json_fail(p, "invalid JSON escape");
          goto fail;
      }
    } else {
      /* Copy the raw UTF-8 byte; the document was validated upfront. */
      utf8_push(&decoded, &len, &cap, c);
      p->pos++;
    }
  }
fail:
  free(decoded);
  return NULL;
}

static Json *json_new(JsonKind kind) {
  Json *v = xmalloc(sizeof(Json));
  memset(v, 0, sizeof(Json));
  v->kind = kind;
  return v;
}

static Json *json_parse_value(JsonParser *p);

static Json *json_parse_number(JsonParser *p) {
  size_t start = p->pos;
  if (json_peek(p) == '-') p->pos++;
  if (json_at_end(p)) {
    json_fail(p, "truncated JSON number");
    return NULL;
  }
  char c = json_peek(p);
  if (c == '0') {
    p->pos++;
  } else if (c >= '1' && c <= '9') {
    while ((c = json_peek(p)) >= '0' && c <= '9') p->pos++;
  } else {
    json_fail(p, "invalid JSON number");
    return NULL;
  }
  int integral = 1;
  if (json_peek(p) == '.') {
    integral = 0;
    p->pos++;
    size_t digits = 0;
    while ((c = json_peek(p)) >= '0' && c <= '9') {
      p->pos++;
      digits++;
    }
    if (digits == 0) {
      json_fail(p, "invalid JSON number");
      return NULL;
    }
  }
  c = json_peek(p);
  if (c == 'e' || c == 'E') {
    integral = 0;
    p->pos++;
    c = json_peek(p);
    if (c == '+' || c == '-') p->pos++;
    size_t digits = 0;
    while ((c = json_peek(p)) >= '0' && c <= '9') {
      p->pos++;
      digits++;
    }
    if (digits == 0) {
      json_fail(p, "invalid JSON number");
      return NULL;
    }
  }
  size_t end = p->pos;
  Json *v;
  if (integral) {
    char tmp[64];
    size_t n = end - start;
    if (n >= sizeof(tmp)) {
      json_fail(p, "JSON integer out of supported range");
      return NULL;
    }
    memcpy(tmp, p->buf + start, n);
    tmp[n] = '\0';
    char *tail;
    errno = 0;
    long long value = strtoll(tmp, &tail, 10);
    if (*tail != '\0' || errno == ERANGE) {
      json_fail(p, "JSON integer out of supported range");
      return NULL;
    }
    v = json_new(J_INT);
    v->integer = value;
  } else {
    char *tmp = xmalloc(end - start + 1);
    memcpy(tmp, p->buf + start, end - start);
    tmp[end - start] = '\0';
    char *tail;
    double value = strtod(tmp, &tail);
    free(tmp);
    if (*tail != '\0' || !isfinite(value)) {
      json_fail(p, "invalid JSON number");
      return NULL;
    }
    v = json_new(J_REAL);
    v->real = value;
  }
  return v;
}

static Json *json_parse_value(JsonParser *p) {
  json_skip_ws(p);
  if (p->failed || json_at_end(p)) {
    json_fail(p, "expected JSON value");
    return NULL;
  }
  char c = json_peek(p);
  if (c == '{') {
    p->depth++;
    if (p->depth > JSON_MAX_DEPTH) {
      json_fail(p, "JSON nesting exceeds protocol limit");
      return NULL;
    }
    p->pos++;
    Json *v = json_new(J_OBJECT);
    size_t cap = 0;
    json_skip_ws(p);
    if (json_peek(p) == '}') {
      p->pos++;
      p->depth--;
      return v;
    }
    for (;;) {
      json_skip_ws(p);
      size_t key_len = 0;
      char *key = json_parse_string_raw(p, &key_len);
      if (!key) {
        json_free(v);
        return NULL;
      }
      for (size_t i = 0; i < v->n; i++) {
        if (strcmp(v->keys[i], key) == 0) {
          set_error("duplicate JSON object member: %s", key);
          free(key);
          json_free(v);
          p->failed = 1;
          return NULL;
        }
      }
      json_skip_ws(p);
      if (json_peek(p) != ':') {
        json_fail(p, "expected colon after JSON object key");
        free(key);
        json_free(v);
        return NULL;
      }
      p->pos++;
      Json *value = json_parse_value(p);
      if (!value) {
        free(key);
        json_free(v);
        return NULL;
      }
      if (v->n == cap) {
        cap = cap ? cap * 2 : 8;
        v->keys = xrealloc(v->keys, cap * sizeof(char *));
        v->values = xrealloc(v->values, cap * sizeof(Json *));
      }
      v->keys[v->n] = key;
      v->values[v->n] = value;
      v->n++;
      json_skip_ws(p);
      char d = json_peek(p);
      if (d == ',') {
        p->pos++;
        continue;
      }
      if (d == '}') {
        p->pos++;
        p->depth--;
        return v;
      }
      json_fail(p, "expected comma or closing brace");
      json_free(v);
      return NULL;
    }
  }
  if (c == '[') {
    p->depth++;
    if (p->depth > JSON_MAX_DEPTH) {
      json_fail(p, "JSON nesting exceeds protocol limit");
      return NULL;
    }
    p->pos++;
    Json *v = json_new(J_ARRAY);
    size_t cap = 0;
    json_skip_ws(p);
    if (json_peek(p) == ']') {
      p->pos++;
      p->depth--;
      return v;
    }
    for (;;) {
      Json *value = json_parse_value(p);
      if (!value) {
        json_free(v);
        return NULL;
      }
      if (v->n == cap) {
        cap = cap ? cap * 2 : 8;
        v->items = xrealloc(v->items, cap * sizeof(Json *));
      }
      v->items[v->n++] = value;
      json_skip_ws(p);
      char d = json_peek(p);
      if (d == ',') {
        p->pos++;
        continue;
      }
      if (d == ']') {
        p->pos++;
        p->depth--;
        return v;
      }
      json_fail(p, "expected comma or closing bracket");
      json_free(v);
      return NULL;
    }
  }
  if (c == '"') {
    size_t len = 0;
    char *s = json_parse_string_raw(p, &len);
    if (!s) return NULL;
    Json *v = json_new(J_STRING);
    v->str = s;
    v->str_len = len;
    return v;
  }
  if (c == 't') {
    if (p->len - p->pos < 4 || strncmp(p->buf + p->pos, "true", 4) != 0) {
      json_fail(p, "invalid JSON literal");
      return NULL;
    }
    p->pos += 4;
    Json *v = json_new(J_BOOL);
    v->boolean = 1;
    return v;
  }
  if (c == 'f') {
    if (p->len - p->pos < 5 || strncmp(p->buf + p->pos, "false", 5) != 0) {
      json_fail(p, "invalid JSON literal");
      return NULL;
    }
    p->pos += 5;
    Json *v = json_new(J_BOOL);
    v->boolean = 0;
    return v;
  }
  if (c == 'n') {
    if (p->len - p->pos < 4 || strncmp(p->buf + p->pos, "null", 4) != 0) {
      json_fail(p, "invalid JSON literal");
      return NULL;
    }
    p->pos += 4;
    return json_new(J_NULL);
  }
  if (c == '-' || (c >= '0' && c <= '9')) {
    return json_parse_number(p);
  }
  json_fail(p, "expected JSON value");
  return NULL;
}

/* Parses one whole document. The entire input must be exactly one value. */
static Json *json_parse_strict(const char *buf, size_t len) {
  if (!utf8_valid(buf, len)) {
    set_error("JSON is not valid UTF-8");
    return NULL;
  }
  JsonParser p;
  p.buf = buf;
  p.len = len;
  p.pos = 0;
  p.depth = 0;
  p.failed = 0;
  Json *v = json_parse_value(&p);
  if (!v) return NULL;
  json_skip_ws(&p);
  if (p.pos != p.len) {
    if (!p.failed) set_error("trailing data after JSON value at offset %zu", p.pos);
    json_free(v);
    return NULL;
  }
  return v;
}

static const Json *obj_get(const Json *v, const char *key) {
  if (!v || v->kind != J_OBJECT) return NULL;
  for (size_t i = 0; i < v->n; i++) {
    if (strcmp(v->keys[i], key) == 0) return v->values[i];
  }
  return NULL;
}

static int json_is_null(const Json *v) {
  return v && v->kind == J_NULL;
}

static int is_nonempty_string(const Json *v) {
  return v && v->kind == J_STRING && v->str_len > 0;
}

/* ------------------------------------------------------------------ */
/* Canonical RFC 3339 UTC timestamps                                   */
/* ------------------------------------------------------------------ */

static int is_leap_year(int y) {
  return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static int days_in_month(int y, int m) {
  static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (m == 2 && is_leap_year(y)) return 29;
  return days[m - 1];
}

static int read_two_digits(const char *s, int *out) {
  if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9') return 0;
  *out = (s[0] - '0') * 10 + (s[1] - '0');
  return 1;
}

/* Accepts exactly YYYY-MM-DDTHH:MM:SSZ with a calendar-valid date. */
static int time_valid(const char *s) {
  if (!s) return 0;
  size_t n = strlen(s);
  if (n != 20) return 0;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (i == 4 || i == 7) {
      if (c != '-') return 0;
    } else if (i == 10) {
      if (c != 'T') return 0;
    } else if (i == 13 || i == 16) {
      if (c != ':') return 0;
    } else if (i == 19) {
      if (c != 'Z') return 0;
    } else if (c < '0' || c > '9') {
      return 0;
    }
  }
  int year, month, day, hour, minute, second;
  year = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
  if (!read_two_digits(s + 5, &month)) return 0;
  if (!read_two_digits(s + 8, &day)) return 0;
  if (!read_two_digits(s + 11, &hour)) return 0;
  if (!read_two_digits(s + 14, &minute)) return 0;
  if (!read_two_digits(s + 17, &second)) return 0;
  if (month < 1 || month > 12) return 0;
  if (day < 1 || day > days_in_month(year, month)) return 0;
  if (hour > 23 || minute > 59 || second > 59) return 0;
  return 1;
}

/* Canonical fixed-width timestamps order chronologically as strings. */
static int time_cmp(const char *a, const char *b) {
  return strcmp(a, b);
}

static long long days_from_civil(long long y, unsigned m, unsigned d) {
  y -= m <= 2;
  long long era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
  unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  return era * 146097LL + (long long)doe - 719468LL;
}

static long long time_seconds(const char *s) {
  long long year = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 +
                   (s[3] - '0');
  long long month = (s[5] - '0') * 10 + (s[6] - '0');
  long long day = (s[8] - '0') * 10 + (s[9] - '0');
  long long hour = (s[11] - '0') * 10 + (s[12] - '0');
  long long minute = (s[14] - '0') * 10 + (s[15] - '0');
  long long second = (s[17] - '0') * 10 + (s[18] - '0');
  return days_from_civil(year, (unsigned)month, (unsigned)day) * 86400LL +
         hour * 3600LL + minute * 60LL + second;
}

static int time_schema_value(const Json *v) {
  return v && v->kind == J_STRING && time_valid(v->str);
}

/* ------------------------------------------------------------------ */
/* SemVer 2.0                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
  const char *p;
  size_t len;
} Slice;

typedef struct {
  long long major, minor, patch;
  Slice pre[32];
  size_t pre_n;
} SemVer;

static int semver_numeric_id(const Slice *id) {
  for (size_t i = 0; i < id->len; i++) {
    if (id->p[i] < '0' || id->p[i] > '9') return 0;
  }
  return 1;
}

/* Numeric identifiers must not carry leading zeros. */
static int semver_valid_id(const Slice *id) {
  if (id->len == 0) return 0;
  for (size_t i = 0; i < id->len; i++) {
    char c = id->p[i];
    int ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
             (c >= 'a' && c <= 'z') || c == '-';
    if (!ok) return 0;
  }
  if (semver_numeric_id(id) && id->len > 1 && id->p[0] == '0') return 0;
  return 1;
}

static int parse_core_number(const char *s, size_t *pos, long long *out) {
  size_t start = *pos;
  if (s[*pos] == '0') {
    (*pos)++;
  } else if (s[*pos] >= '1' && s[*pos] <= '9') {
    while (s[*pos] >= '0' && s[*pos] <= '9') (*pos)++;
  } else {
    return 0;
  }
  long long value = 0;
  for (size_t i = start; i < *pos; i++) {
    value = value * 10 + (s[i] - '0');
  }
  *out = value;
  return 1;
}

static int semver_parse(const char *s, SemVer *out) {
  memset(out, 0, sizeof(*out));
  size_t pos = 0;
  if (!parse_core_number(s, &pos, &out->major)) return 0;
  if (s[pos] != '.') return 0;
  pos++;
  if (!parse_core_number(s, &pos, &out->minor)) return 0;
  if (s[pos] != '.') return 0;
  pos++;
  if (!parse_core_number(s, &pos, &out->patch)) return 0;
  if (s[pos] == '-') {
    pos++;
    size_t id_start = pos;
    for (;;) {
      char c = s[pos];
      if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
          (c >= 'a' && c <= 'z') || c == '-') {
        pos++;
        continue;
      }
      if (c == '.' || c == '\0' || c == '+') {
        Slice id = {s + id_start, pos - id_start};
        if (out->pre_n >= 32 || !semver_valid_id(&id)) return 0;
        out->pre[out->pre_n++] = id;
        if (c == '.') {
          pos++;
          id_start = pos;
          continue;
        }
        break;
      }
      return 0;
    }
  }
  if (s[pos] == '+') {
    pos++;
    size_t id_start = pos;
    for (;;) {
      char c = s[pos];
      if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
          (c >= 'a' && c <= 'z') || c == '-') {
        pos++;
        continue;
      }
      if (c == '.') {
        Slice id = {s + id_start, pos - id_start};
        if (!semver_valid_id(&id)) return 0;
        pos++;
        id_start = pos;
        continue;
      }
      if (c == '\0') {
        Slice id = {s + id_start, pos - id_start};
        if (!semver_valid_id(&id)) return 0;
        break;
      }
      return 0;
    }
  }
  return s[pos] == '\0';
}

static int slice_numeric_cmp(const Slice *a, const Slice *b) {
  if (a->len != b->len) return a->len < b->len ? -1 : 1;
  int c = memcmp(a->p, b->p, a->len);
  return c < 0 ? -1 : c > 0 ? 1 : 0;
}

static int slice_lex_cmp(const Slice *a, const Slice *b) {
  size_t n = a->len < b->len ? a->len : b->len;
  int c = memcmp(a->p, b->p, n);
  if (c != 0) return c < 0 ? -1 : 1;
  if (a->len == b->len) return 0;
  return a->len < b->len ? -1 : 1;
}

static int semver_compare(const SemVer *a, const SemVer *b) {
  if (a->major != b->major) return a->major < b->major ? -1 : 1;
  if (a->minor != b->minor) return a->minor < b->minor ? -1 : 1;
  if (a->patch != b->patch) return a->patch < b->patch ? -1 : 1;
  if (a->pre_n == 0 && b->pre_n == 0) return 0;
  if (a->pre_n == 0) return 1;
  if (b->pre_n == 0) return -1;
  size_t n = a->pre_n < b->pre_n ? a->pre_n : b->pre_n;
  for (size_t i = 0; i < n; i++) {
    int a_num = semver_numeric_id(&a->pre[i]);
    int b_num = semver_numeric_id(&b->pre[i]);
    int c;
    if (a_num && b_num) {
      c = slice_numeric_cmp(&a->pre[i], &b->pre[i]);
    } else if (a_num) {
      c = -1;
    } else if (b_num) {
      c = 1;
    } else {
      c = slice_lex_cmp(&a->pre[i], &b->pre[i]);
    }
    if (c != 0) return c;
  }
  if (a->pre_n == b->pre_n) return 0;
  return a->pre_n < b->pre_n ? -1 : 1;
}

/* ------------------------------------------------------------------ */
/* Trust store                                                         */
/* ------------------------------------------------------------------ */

#define TRUST_MAX_KEYS 16

typedef struct {
  char *id;
  unsigned char raw_key[32];
  char *status;
  char *not_before; /* NULL when JSON null */
  char *not_after;  /* NULL when JSON null */
  const char *purposes[8];
  size_t purpose_n;
} TrustKey;

typedef struct {
  char *issuer;
  TrustKey keys[TRUST_MAX_KEYS];
  size_t key_n;
} TrustStore;

void trust_store_free(TrustStore *store);

static int status_allowed(const char *s) {
  return str_equals(s, "active") || str_equals(s, "next") ||
         str_equals(s, "retired") || str_equals(s, "revoked");
}

static int purpose_allowed(const char *s) {
  return str_equals(s, "entitlement") || str_equals(s, "trial") ||
         str_equals(s, "trial-extension") || str_equals(s, "activation");
}

static int object_exact(const Json *v, const char *const *names, size_t n) {
  if (!v || v->kind != J_OBJECT || v->n != n) return 0;
  for (size_t i = 0; i < n; i++) {
    if (!obj_get(v, names[i])) return 0;
  }
  return 1;
}

static int is_int_ge(const Json *v, long long floor) {
  return v && v->kind == J_INT && v->integer >= floor;
}

static int is_unique_string_list(const Json *v) {
  if (!v || v->kind != J_ARRAY) return 0;
  for (size_t i = 0; i < v->n; i++) {
    if (!is_nonempty_string(v->items[i])) return 0;
    for (size_t k = 0; k < i; k++) {
      if (strcmp(v->items[i]->str, v->items[k]->str) == 0) return 0;
    }
  }
  return 1;
}

static int string_list_contains(const Json *v, const char *s) {
  if (!v || v->kind != J_ARRAY) return 0;
  for (size_t i = 0; i < v->n; i++) {
    if (v->items[i]->kind == J_STRING && str_equals(v->items[i]->str, s)) return 1;
  }
  return 0;
}

TrustStore *trust_store_parse(const Json *root) {
  static const char *top_fields[] = {"issuer", "keys", "protocol", "version"};
  if (!object_exact(root, top_fields, 4)) {
    set_error("unexpected trust store fields");
    return NULL;
  }
  const Json *protocol = obj_get(root, "protocol");
  if (!protocol || protocol->kind != J_STRING ||
      !str_equals(protocol->str, "permit-trust-store")) {
    set_error("invalid protocol");
    return NULL;
  }
  const Json *version = obj_get(root, "version");
  if (!version || version->kind != J_INT || version->integer != 1) {
    set_error("unsupported version");
    return NULL;
  }
  const Json *issuer = obj_get(root, "issuer");
  if (!is_nonempty_string(issuer)) {
    set_error("invalid issuer");
    return NULL;
  }
  const Json *keys = obj_get(root, "keys");
  if (!keys || keys->kind != J_OBJECT || keys->n == 0) {
    set_error("keys must be a non-empty JSON object");
    return NULL;
  }
  TrustStore *store = xmalloc(sizeof(TrustStore));
  memset(store, 0, sizeof(*store));
  store->issuer = xstrdup(issuer->str);
  for (size_t i = 0; i < keys->n; i++) {
    if (store->key_n >= TRUST_MAX_KEYS) {
      set_error("too many trust keys");
      trust_store_free(store);
      return NULL;
    }
    const char *id = keys->keys[i];
    const Json *entry = keys->values[i];
    if (strlen(id) == 0) {
      set_error("key_id must be non-empty");
      trust_store_free(store);
      return NULL;
    }
    static const char *key_fields[] = {"algorithm", "not_after", "not_before",
                                       "public_key", "purposes", "status"};
    if (!object_exact(entry, key_fields, 6)) {
      set_error("unexpected trust key fields for %s", id);
      trust_store_free(store);
      return NULL;
    }
    const Json *algorithm = obj_get(entry, "algorithm");
    if (!algorithm || algorithm->kind != J_STRING ||
        !str_equals(algorithm->str, "Ed25519")) {
      set_error("unsupported key algorithm for %s", id);
      trust_store_free(store);
      return NULL;
    }
    const Json *status = obj_get(entry, "status");
    if (!status || status->kind != J_STRING || !status_allowed(status->str)) {
      set_error("invalid key status for %s", id);
      trust_store_free(store);
      return NULL;
    }
    const Json *public_key = obj_get(entry, "public_key");
    if (!is_nonempty_string(public_key)) {
      set_error("invalid public_key for %s", id);
      trust_store_free(store);
      return NULL;
    }
    const Json *purposes = obj_get(entry, "purposes");
    if (!purposes || purposes->kind != J_ARRAY || purposes->n == 0 ||
        purposes->n > 8) {
      set_error("invalid trust-key purposes for %s", id);
      trust_store_free(store);
      return NULL;
    }
    TrustKey *tk = &store->keys[store->key_n];
    memset(tk, 0, sizeof(*tk));
    tk->id = xstrdup(id);
    tk->status = xstrdup(status->str);
    for (size_t k = 0; k < purposes->n; k++) {
      const Json *p = purposes->items[k];
      if (!is_nonempty_string(p) || !purpose_allowed(p->str)) {
        set_error("invalid trust-key purposes for %s", id);
        trust_store_free(store);
        return NULL;
      }
      for (size_t prev = 0; prev < k; prev++) {
        if (str_equals(tk->purposes[prev], p->str)) {
          set_error("invalid trust-key purposes for %s", id);
          trust_store_free(store);
          return NULL;
        }
      }
      tk->purposes[tk->purpose_n++] = xstrdup(p->str);
    }
    const Json *nb = obj_get(entry, "not_before");
    const Json *na = obj_get(entry, "not_after");
    if (!json_is_null(nb) && !time_schema_value(nb)) {
      set_error("invalid key not_before for %s", id);
      trust_store_free(store);
      return NULL;
    }
    if (!json_is_null(na) && !time_schema_value(na)) {
      set_error("invalid key not_after for %s", id);
      trust_store_free(store);
      return NULL;
    }
    tk->not_before = json_is_null(nb) ? NULL : xstrdup(nb->str);
    tk->not_after = json_is_null(na) ? NULL : xstrdup(na->str);
    if (tk->not_before && tk->not_after && time_cmp(tk->not_before, tk->not_after) > 0) {
      set_error("trust-key not_before must not exceed not_after for %s", id);
      trust_store_free(store);
      return NULL;
    }
    if (str_equals(tk->status, "next") && !tk->not_before) {
      set_error("next key requires a not_before issuance boundary");
      trust_store_free(store);
      return NULL;
    }
    if (str_equals(tk->status, "retired") && !tk->not_after) {
      set_error("retired key requires a not_after issuance boundary");
      trust_store_free(store);
      return NULL;
    }
    Bytes der = {NULL, 0};
    int decode = b64_decode(public_key->str, strlen(public_key->str), &der);
    if (decode != 0 || !ed25519_raw_from_spki(der.data, der.len, tk->raw_key)) {
      set_error("could not decode Ed25519 key for %s", id);
      bytes_free(&der);
      trust_store_free(store);
      return NULL;
    }
    bytes_free(&der);
    /* One public key must not appear under multiple key ids. */
    for (size_t prev = 0; prev < store->key_n; prev++) {
      if (memcmp(store->keys[prev].raw_key, tk->raw_key, 32) == 0) {
        set_error("the same public key must not appear under multiple key ids "
                  "(%s and %s)",
                  store->keys[prev].id, id);
        trust_store_free(store);
        return NULL;
      }
    }
    store->key_n++;
  }
  return store;
}

void trust_store_free(TrustStore *store) {
  if (!store) return;
  free(store->issuer);
  for (size_t i = 0; i < store->key_n; i++) {
    free(store->keys[i].id);
    free(store->keys[i].status);
    free(store->keys[i].not_before);
    free(store->keys[i].not_after);
    for (size_t k = 0; k < store->keys[i].purpose_n; k++) {
      free((void *)store->keys[i].purposes[k]);
    }
  }
  free(store);
}

/* Mirrors trust-store-key: unknown ids and revoked keys reject here. */
static const TrustKey *trust_store_lookup(const TrustStore *store, const char *key_id) {
  for (size_t i = 0; i < store->key_n; i++) {
    if (str_equals(store->keys[i].id, key_id)) {
      if (str_equals(store->keys[i].status, "revoked")) {
        set_error("signing key is revoked");
        return NULL;
      }
      return &store->keys[i];
    }
  }
  set_error("unknown key_id");
  return NULL;
}

/* Key windows constrain issued_at, not the verification wall clock. */
static int trust_key_covers_issued_at(const TrustKey *key, const char *issued_at) {
  if (key->not_before && time_cmp(key->not_before, issued_at) > 0) return 0;
  if (key->not_after && time_cmp(issued_at, key->not_after) > 0) return 0;
  return 1;
}

static int trust_key_allows_purpose(const TrustKey *key, const char *purpose) {
  for (size_t i = 0; i < key->purpose_n; i++) {
    if (str_equals(key->purposes[i], purpose)) return 1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Payload schema validation                                           */
/* ------------------------------------------------------------------ */

#define SCHECK(cond, ...)                         \
  do {                                            \
    if (!(cond)) {                                \
      set_schema_error(__VA_ARGS__);              \
      return 0;                                   \
    }                                             \
  } while (0)

/* Schema failures report through the shared g_error buffer. */
static void set_schema_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(g_error, sizeof(g_error), fmt, args);
  va_end(args);
}

static int is_credential_type(const Json *v, const char *a, const char *b) {
  return v && v->kind == J_STRING &&
         (str_equals(v->str, a) || (b && str_equals(v->str, b)));
}

static int is_version_one(const Json *v) {
  return v && v->kind == J_INT && v->integer == 1;
}

static int is_scalar_capability(const Json *v) {
  return v && (v->kind == J_STRING || v->kind == J_BOOL || v->kind == J_INT ||
               v->kind == J_REAL);
}

static int validate_base_claims(const Json *claims, const char *const *fields,
                                size_t n_fields, const char *label) {
  SCHECK(object_exact(claims, fields, n_fields), "unexpected %s fields", label);
  const Json *protocol = obj_get(claims, "protocol");
  SCHECK(protocol && protocol->kind == J_STRING && str_equals(protocol->str, "permit"),
         "invalid protocol");
  SCHECK(is_version_one(obj_get(claims, "version")), "unsupported protocol version");
  SCHECK(is_nonempty_string(obj_get(claims, "credential_id")), "invalid credential_id");
  SCHECK(is_nonempty_string(obj_get(claims, "issuer")), "invalid issuer");
  SCHECK(time_schema_value(obj_get(claims, "issued_at")), "invalid issued_at");
  const Json *not_before = obj_get(claims, "not_before");
  SCHECK(json_is_null(not_before) || time_schema_value(not_before),
         "invalid not_before");
  SCHECK(obj_get(claims, "extensions") && obj_get(claims, "extensions")->kind == J_OBJECT,
         "invalid extensions");
  return 1;
}

static int validate_subject(const Json *subject) {
  static const char *fields[] = {"display", "id", "type"};
  SCHECK(object_exact(subject, fields, 3), "unexpected subject fields");
  static const char *const subject_types[] = {"person", "organization", "account",
                                              "device", "installation", "anonymous"};
  const Json *type = obj_get(subject, "type");
  int found = 0;
  for (size_t i = 0; i < 6 && !found; i++) {
    found = type && type->kind == J_STRING && str_equals(type->str, subject_types[i]);
  }
  SCHECK(found, "invalid subject.type");
  SCHECK(is_nonempty_string(obj_get(subject, "id")), "invalid subject.id");
  const Json *display = obj_get(subject, "display");
  SCHECK(json_is_null(display) || (display && display->kind == J_STRING),
         "invalid subject.display");
  return 1;
}

static int validate_scope(const Json *scope) {
  static const char *fields[] = {"product_families", "products"};
  SCHECK(object_exact(scope, fields, 2), "unexpected scope fields");
  SCHECK(is_unique_string_list(obj_get(scope, "products")),
         "invalid scope.products");
  SCHECK(is_unique_string_list(obj_get(scope, "product_families")),
         "invalid scope.product_families");
  const Json *products = obj_get(scope, "products");
  const Json *families = obj_get(scope, "product_families");
  SCHECK(products->n > 0 || families->n > 0,
         "scope must name a product or product family");
  return 1;
}

static int validate_version_policy(const Json *policy) {
  static const char *fields[] = {"max", "min"};
  SCHECK(object_exact(policy, fields, 2),
         "unexpected constraints.version_policy fields");
  const Json *min = obj_get(policy, "min");
  const Json *max = obj_get(policy, "max");
  SCHECK(json_is_null(min) || (min->kind == J_STRING && semver_parse(min->str, &(SemVer){0})),
         "invalid constraints.version_policy.min");
  SCHECK(json_is_null(max) || (max->kind == J_STRING && semver_parse(max->str, &(SemVer){0})),
         "invalid constraints.version_policy.max");
  const char *min_s = json_is_null(min) ? NULL : min->str;
  const char *max_s = json_is_null(max) ? NULL : max->str;
  if (min_s && max_s) {
    SemVer a, b;
    semver_parse(min_s, &a);
    semver_parse(max_s, &b);
    SCHECK(semver_compare(&a, &b) <= 0,
           "version policy minimum must not exceed maximum");
  }
  return 1;
}

static int validate_grant(const Json *grant) {
  static const char *fields[] = {"addons", "capabilities", "edition",
                                 "feature_policy", "features", "scope"};
  SCHECK(object_exact(grant, fields, 6), "unexpected grant fields");
  SCHECK(validate_scope(obj_get(grant, "scope")), "invalid grant scope");
  const Json *edition = obj_get(grant, "edition");
  SCHECK(json_is_null(edition) || is_nonempty_string(edition), "invalid grant.edition");
  const Json *policy = obj_get(grant, "feature_policy");
  SCHECK(policy && policy->kind == J_STRING &&
             (str_equals(policy->str, "explicit") ||
              str_equals(policy->str, "published-through")),
         "invalid grant.feature_policy");
  const Json *features = obj_get(grant, "features");
  SCHECK(is_unique_string_list(features), "invalid grant.features");
  SCHECK(!string_list_contains(features, "*"),
         "feature id * is reserved; use feature_policy=published-through");
  SCHECK(!(policy && policy->kind == J_STRING &&
           str_equals(policy->str, "published-through") && features->n > 0),
         "published-through grants must leave features empty; compose a separate "
         "explicit grant");
  SCHECK(is_unique_string_list(obj_get(grant, "addons")), "invalid grant.addons");
  const Json *capabilities = obj_get(grant, "capabilities");
  SCHECK(capabilities && capabilities->kind == J_OBJECT,
         "invalid grant.capabilities");
  if (capabilities && capabilities->kind == J_OBJECT) {
    for (size_t i = 0; i < capabilities->n; i++) {
      SCHECK(is_scalar_capability(capabilities->values[i]),
             "invalid capability value");
    }
  }
  return 1;
}

static int validate_constraints(const Json *constraints, const char *type) {
  static const char *fields[] = {"activation_required", "features_through",
                                 "installation_id", "limits", "updates_through",
                                 "use_expires_at", "version_policy"};
  SCHECK(object_exact(constraints, fields, 7), "unexpected constraints fields");
  static const char *const times[] = {"use_expires_at", "updates_through",
                                      "features_through"};
  for (size_t i = 0; i < 3; i++) {
    const Json *t = obj_get(constraints, times[i]);
    SCHECK(json_is_null(t) || time_schema_value(t), "invalid constraints timestamp");
  }
  if (str_equals(type, "trial")) {
    SCHECK(!json_is_null(obj_get(constraints, "use_expires_at")),
           "trial must have a finite use_expires_at");
  }
  const Json *installation = obj_get(constraints, "installation_id");
  SCHECK(json_is_null(installation) || is_nonempty_string(installation),
         "invalid constraints.installation_id");
  const Json *activation_required = obj_get(constraints, "activation_required");
  SCHECK(activation_required && activation_required->kind == J_BOOL,
         "invalid constraints.activation_required");
  const Json *limits = obj_get(constraints, "limits");
  static const char *limit_fields[] = {"concurrent_seats", "device_activations",
                                       "named_seats"};
  SCHECK(object_exact(limits, limit_fields, 3), "unexpected constraints.limits fields");
  for (size_t i = 0; i < 3; i++) {
    const Json *value = obj_get(limits, limit_fields[i]);
    SCHECK(json_is_null(value) || is_int_ge(value, 0),
           "invalid constraints.limits value");
  }
  SCHECK(validate_version_policy(obj_get(constraints, "version_policy")),
         "invalid constraints.version_policy");
  return 1;
}

static int validate_entitlement_like(const Json *claims) {
  static const char *fields[] = {
      "channel", "constraints", "credential_id", "entitlement_id", "extensions",
      "grants", "issued_at", "issuer", "not_before", "protocol", "revision",
      "subject", "type", "version"};
  SCHECK(validate_base_claims(claims, fields, 14, "credential"),
         "invalid credential base");
  const Json *type = obj_get(claims, "type");
  SCHECK(is_credential_type(type, "entitlement", "trial"),
         "unsupported entitlement-like type");
  SCHECK(is_nonempty_string(obj_get(claims, "entitlement_id")),
         "invalid entitlement_id");
  SCHECK(is_int_ge(obj_get(claims, "revision"), 0), "invalid revision");
  SCHECK(validate_subject(obj_get(claims, "subject")), "invalid subject");
  SCHECK(is_nonempty_string(obj_get(claims, "channel")), "invalid channel");
  const Json *grants = obj_get(claims, "grants");
  SCHECK(grants && grants->kind == J_ARRAY, "invalid grants");
  SCHECK(grants->n > 0, "credential must contain at least one grant");
  for (size_t i = 0; i < grants->n; i++) {
    SCHECK(validate_grant(grants->items[i]), "invalid grant");
  }
  SCHECK(validate_constraints(obj_get(claims, "constraints"), type->str),
         "invalid constraints");
  return 1;
}

static int validate_activation_claims(const Json *claims) {
  static const char *fields[] = {
      "credential_id", "entitlement_credential_id", "entitlement_id",
      "entitlement_revision", "extensions", "installation_id", "issued_at",
      "issuer", "lease_id", "not_before", "offline_grace_seconds", "protocol",
      "type", "valid_until", "version"};
  SCHECK(validate_base_claims(claims, fields, 15, "activation credential"),
         "invalid activation base");
  const Json *type = obj_get(claims, "type");
  SCHECK(type && type->kind == J_STRING && str_equals(type->str, "activation"),
         "invalid activation type");
  static const char *const ids[] = {"entitlement_credential_id", "entitlement_id",
                                    "installation_id", "lease_id"};
  for (size_t i = 0; i < 4; i++) {
    SCHECK(is_nonempty_string(obj_get(claims, ids[i])), "invalid activation id field");
  }
  SCHECK(is_int_ge(obj_get(claims, "entitlement_revision"), 0),
         "invalid entitlement_revision");
  SCHECK(time_schema_value(obj_get(claims, "valid_until")), "invalid valid_until");
  SCHECK(time_cmp(obj_get(claims, "issued_at")->str, obj_get(claims, "valid_until")->str) <= 0,
         "activation valid_until must not precede issued_at");
  SCHECK(is_int_ge(obj_get(claims, "offline_grace_seconds"), 0),
         "invalid offline_grace_seconds");
  return 1;
}

static int validate_trial_extension_claims(const Json *claims) {
  static const char *fields[] = {"credential_id", "extensions", "issued_at",
                                 "issuer", "not_before", "protocol", "trial_id",
                                 "type", "use_expires_at", "version"};
  SCHECK(validate_base_claims(claims, fields, 10, "trial-extension credential"),
         "invalid trial-extension base");
  const Json *type = obj_get(claims, "type");
  SCHECK(type && type->kind == J_STRING && str_equals(type->str, "trial-extension"),
         "invalid trial-extension type");
  SCHECK(is_nonempty_string(obj_get(claims, "trial_id")), "invalid trial_id");
  SCHECK(time_schema_value(obj_get(claims, "use_expires_at")),
         "invalid use_expires_at");
  SCHECK(time_cmp(obj_get(claims, "issued_at")->str,
                  obj_get(claims, "use_expires_at")->str) <= 0,
         "trial extension must not expire before it is issued");
  return 1;
}

static int validate_credential_claims(const Json *claims) {
  SCHECK(claims && claims->kind == J_OBJECT, "credential must be a JSON object");
  const Json *type = obj_get(claims, "type");
  if (is_credential_type(type, "entitlement", "trial")) {
    return validate_entitlement_like(claims);
  }
  if (type && type->kind == J_STRING && str_equals(type->str, "activation")) {
    return validate_activation_claims(claims);
  }
  if (type && type->kind == J_STRING && str_equals(type->str, "trial-extension")) {
    return validate_trial_extension_claims(claims);
  }
  set_schema_error("unsupported credential type");
  return 0;
}

/* ------------------------------------------------------------------ */
/* Verification pipeline                                               */
/* ------------------------------------------------------------------ */

typedef enum {
  VERIFY_OK = 0,
  ERR_JSON_STRUCTURAL,
  ERR_ENVELOPE,
  ERR_TRUST_STORE,
  ERR_UNKNOWN_KEY,
  ERR_REVOKED_KEY,
  ERR_SIGNATURE,
  ERR_PAYLOAD,
  ERR_ISSUER_MISMATCH,
  ERR_ISSUANCE_WINDOW,
  ERR_KEY_PURPOSE,
  ERR_LINEAGE_CONFLICT,
  ERR_LINEAGE_MISMATCH
} Outcome;

static const char *outcome_name(Outcome o) {
  switch (o) {
    case VERIFY_OK: return "verify";
    case ERR_JSON_STRUCTURAL: return "json-structural-reject";
    case ERR_ENVELOPE: return "envelope-reject";
    case ERR_TRUST_STORE: return "trust-store-reject";
    case ERR_UNKNOWN_KEY: return "unknown-key-reject";
    case ERR_REVOKED_KEY: return "revoked-key-reject";
    case ERR_SIGNATURE: return "signature-reject";
    case ERR_PAYLOAD: return "payload-reject";
    case ERR_ISSUER_MISMATCH: return "issuer-mismatch-reject";
    case ERR_ISSUANCE_WINDOW: return "issuance-window-reject";
    case ERR_KEY_PURPOSE: return "key-purpose-reject";
    case ERR_LINEAGE_CONFLICT: return "lineage-conflict-reject";
    case ERR_LINEAGE_MISMATCH: return "lineage-mismatch-reject";
  }
  return "?";
}

/*
 * Verifies one credential file. On VERIFY_OK the parsed claims are stored in
 * *claims_out (owned by *envelope_out; the caller frees both with json_free).
 * Order mirrors verify-credential: envelope structure, key lookup, signature,
 * payload schema, issuer, issuance window, key purpose.
 */
static Outcome verify_credential_file(const char *path, const TrustStore *store,
                                      const Json **claims_out, Json **envelope_out) {
  Bytes file = read_whole_file(path);
  if (!file.data) return ERR_ENVELOPE;
  Json *envelope = json_parse_strict((const char *)file.data, file.len);
  bytes_free(&file);
  if (!envelope) return ERR_JSON_STRUCTURAL;

  static const char *envelope_fields[] = {"algorithm", "key_id", "payload",
                                          "permit_version", "signature"};
  if (!object_exact(envelope, envelope_fields, 5)) {
    set_error("unexpected envelope fields");
    json_free(envelope);
    return ERR_ENVELOPE;
  }
  if (!is_version_one(obj_get(envelope, "permit_version"))) {
    set_error("unsupported permit_version");
    json_free(envelope);
    return ERR_ENVELOPE;
  }
  const Json *algorithm = obj_get(envelope, "algorithm");
  if (!algorithm || algorithm->kind != J_STRING ||
      !str_equals(algorithm->str, "Ed25519")) {
    set_error("unsupported algorithm");
    json_free(envelope);
    return ERR_ENVELOPE;
  }
  const Json *key_id = obj_get(envelope, "key_id");
  if (!is_nonempty_string(key_id)) {
    set_error("invalid key_id");
    json_free(envelope);
    return ERR_ENVELOPE;
  }
  const Json *payload_field = obj_get(envelope, "payload");
  const Json *signature_field = obj_get(envelope, "signature");
  if (!payload_field || payload_field->kind != J_STRING ||
      !signature_field || signature_field->kind != J_STRING) {
    set_error("invalid base64 envelope field");
    json_free(envelope);
    return ERR_ENVELOPE;
  }
  Bytes payload = {NULL, 0};
  Bytes signature = {NULL, 0};
  int payload_ok = b64_decode(payload_field->str, strlen(payload_field->str), &payload);
  int signature_ok =
      b64_decode(signature_field->str, strlen(signature_field->str), &signature);
  if (payload_ok != 0 || signature_ok != 0 || signature.len != 64) {
    set_error("invalid base64 envelope field or signature length");
    bytes_free(&payload);
    bytes_free(&signature);
    json_free(envelope);
    return ERR_ENVELOPE;
  }

  const TrustKey *key = trust_store_lookup(store, key_id->str);
  if (!key) {
    Outcome o = strstr(g_error, "revoked") ? ERR_REVOKED_KEY : ERR_UNKNOWN_KEY;
    bytes_free(&payload);
    bytes_free(&signature);
    json_free(envelope);
    return o;
  }
  if (!ed25519_verify(key->raw_key, payload.data, payload.len, signature.data,
                      signature.len)) {
    set_error("invalid Ed25519 signature");
    bytes_free(&payload);
    bytes_free(&signature);
    json_free(envelope);
    return ERR_SIGNATURE;
  }

  /* Only cross the semantic parsing boundary after authentication. */
  Json *claims = json_parse_strict((const char *)payload.data, payload.len);
  bytes_free(&payload);
  bytes_free(&signature);
  if (!claims) return ERR_PAYLOAD;
  if (!validate_credential_claims(claims)) {
    json_free(claims);
    return ERR_PAYLOAD;
  }
  const Json *issuer = obj_get(claims, "issuer");
  if (!str_equals(issuer->str, store->issuer)) {
    json_free(claims);
    return ERR_ISSUER_MISMATCH;
  }
  const Json *issued_at = obj_get(claims, "issued_at");
  if (!trust_key_covers_issued_at(key, issued_at->str)) {
    json_free(claims);
    return ERR_ISSUANCE_WINDOW;
  }
  const Json *type = obj_get(claims, "type");
  if (!trust_key_allows_purpose(key, type->str)) {
    json_free(claims);
    return ERR_KEY_PURPOSE;
  }
  if (claims_out && envelope_out) {
    *claims_out = claims;
    *envelope_out = envelope;
  } else {
    json_free(claims);
    json_free(envelope);
  }
  return VERIFY_OK;
}

/* ------------------------------------------------------------------ */
/* Policy evaluation                                                   */
/* ------------------------------------------------------------------ */

#define MAX_REASONS 8
#define MAX_EXTENSIONS 8

typedef struct {
  int usable;
  const char *reasons[MAX_REASONS];
  size_t reason_n;
} CredentialStatus;

static const Json *claims_constraints(const Json *claims) {
  return obj_get(claims, "constraints");
}

static int claims_entitlement_like(const Json *claims) {
  return is_credential_type(obj_get(claims, "type"), "entitlement", "trial");
}

static int time_active(const Json *claims, const char *at) {
  const char *issued_at = obj_get(claims, "issued_at")->str;
  const Json *not_before = obj_get(claims, "not_before");
  if (time_cmp(issued_at, at) > 0) return 0;
  if (!json_is_null(not_before) && time_cmp(not_before->str, at) > 0) return 0;
  return 1;
}

static int trial_extension_valid(const Json *trial, const Json *extension,
                                 const char *at) {
  if (!str_equals(obj_get(trial, "type")->str, "trial")) return 0;
  if (!str_equals(obj_get(extension, "type")->str, "trial-extension")) return 0;
  if (!time_active(extension, at)) return 0;
  if (!str_equals(obj_get(extension, "issuer")->str, obj_get(trial, "issuer")->str)) {
    return 0;
  }
  return str_equals(obj_get(extension, "trial_id")->str,
                    obj_get(trial, "entitlement_id")->str);
}

static int activation_valid(const Json *entitlement, const Json *activation,
                            const char *installation_id, const char *at) {
  if (!claims_entitlement_like(entitlement)) return 0;
  if (!str_equals(obj_get(activation, "type")->str, "activation")) return 0;
  if (!time_active(activation, at)) return 0;
  if (!str_equals(obj_get(activation, "issuer")->str,
                  obj_get(entitlement, "issuer")->str)) return 0;
  if (!str_equals(obj_get(activation, "entitlement_id")->str,
                  obj_get(entitlement, "entitlement_id")->str)) return 0;
  if (!str_equals(obj_get(activation, "entitlement_credential_id")->str,
                  obj_get(entitlement, "credential_id")->str)) return 0;
  const Json *rev = obj_get(activation, "entitlement_revision");
  const Json *ent_rev = obj_get(entitlement, "revision");
  if (!rev || !ent_rev || rev->kind != J_INT || ent_rev->kind != J_INT ||
      rev->integer != ent_rev->integer) return 0;
  if (!str_equals(obj_get(activation, "installation_id")->str, installation_id)) {
    return 0;
  }
  long long at_secs = time_seconds(at);
  long long until = time_seconds(obj_get(activation, "valid_until")->str);
  long long grace = obj_get(activation, "offline_grace_seconds")->integer;
  long long deadline =
      (grace > 0 && until > LLONG_MAX - grace) ? LLONG_MAX : until + grace;
  return at_secs <= deadline;
}

static CredentialStatus credential_status(const Json *claims, const char *at,
                                          const char *installation_id,
                                          const Json *activation,
                                          const Json **extensions,
                                          size_t extension_n) {
  CredentialStatus status;
  memset(&status, 0, sizeof(status));
  const Json *constraints = claims_constraints(claims);

  if (time_cmp(obj_get(claims, "issued_at")->str, at) > 0) {
    status.reasons[status.reason_n++] = "issued-in-future";
  }
  const Json *not_before = obj_get(claims, "not_before");
  if (!json_is_null(not_before) && time_cmp(not_before->str, at) > 0) {
    status.reasons[status.reason_n++] = "not-active-yet";
  }

  const char *use_expires_at = json_is_null(obj_get(constraints, "use_expires_at"))
                                   ? NULL
                                   : obj_get(constraints, "use_expires_at")->str;
  if (str_equals(obj_get(claims, "type")->str, "trial")) {
    for (size_t i = 0; i < extension_n; i++) {
      if (!trial_extension_valid(claims, extensions[i], at)) continue;
      const char *candidate = obj_get(extensions[i], "use_expires_at")->str;
      if (use_expires_at == NULL || time_cmp(use_expires_at, candidate) <= 0) {
        use_expires_at = candidate;
      }
    }
  }
  if (use_expires_at && time_cmp(at, use_expires_at) > 0) {
    status.reasons[status.reason_n++] = "use-expired";
  }

  const Json *bound = obj_get(constraints, "installation_id");
  if (!json_is_null(bound) &&
      (installation_id == NULL || !str_equals(bound->str, installation_id))) {
    status.reasons[status.reason_n++] = "installation-mismatch";
  }

  const Json *activation_required = obj_get(constraints, "activation_required");
  if (activation_required && activation_required->boolean) {
    if (!activation) {
      status.reasons[status.reason_n++] = "activation-required";
    } else if (!installation_id) {
      status.reasons[status.reason_n++] = "installation-id-required";
    } else if (!activation_valid(claims, activation, installation_id, at)) {
      status.reasons[status.reason_n++] = "activation-invalid";
    }
  }

  status.usable = status.reason_n == 0;
  return status;
}

static int version_policy_allowed(const Json *claims, const char *version) {
  const Json *policy = obj_get(claims_constraints(claims), "version_policy");
  const Json *min = obj_get(policy, "min");
  const Json *max = obj_get(policy, "max");
  if (!json_is_null(min)) {
    SemVer a, b;
    semver_parse(version, &a);
    semver_parse(min->str, &b);
    if (semver_compare(&a, &b) < 0) return 0;
  }
  if (!json_is_null(max)) {
    SemVer a, b;
    semver_parse(version, &a);
    semver_parse(max->str, &b);
    if (semver_compare(&a, &b) > 0) return 0;
  }
  return 1;
}

static int version_policy_satisfied(const Json *claims, const char *version) {
  const Json *policy = obj_get(claims_constraints(claims), "version_policy");
  int constrained = !json_is_null(obj_get(policy, "min")) ||
                    !json_is_null(obj_get(policy, "max"));
  if (!constrained) return 1;
  if (!version) return 0;
  return version_policy_allowed(claims, version);
}

static int base_policy_ok(const Json *claims, const char *at,
                          const char *installation_id, const Json *activation,
                          const Json **extensions, size_t extension_n,
                          const char *version) {
  CredentialStatus status =
      credential_status(claims, at, installation_id, activation, extensions,
                        extension_n);
  if (!status.usable) return 0;
  return version_policy_satisfied(claims, version);
}

static int grant_matches_scope(const Json *grant, const char *product,
                               const char *product_family) {
  const Json *scope = obj_get(grant, "scope");
  if (string_list_contains(obj_get(scope, "products"), product)) return 1;
  return product_family &&
         string_list_contains(obj_get(scope, "product_families"), product_family);
}

static int window_allows(const Json *claims, const char *constraint_name,
                         const char *published_at) {
  const Json *cutoff = obj_get(claims_constraints(claims), constraint_name);
  if (json_is_null(cutoff)) return 1;
  return published_at && time_cmp(published_at, cutoff->str) <= 0;
}

static int feature_entitled(const Json *claims, const char *product,
                            const char *feature, const char *published_at,
                            const char *at, const char *product_family,
                            const char *version, const char *installation_id,
                            const Json *activation, const Json **extensions,
                            size_t extension_n) {
  if (!base_policy_ok(claims, at, installation_id, activation, extensions,
                      extension_n, version)) return 0;
  const Json *grants = obj_get(claims, "grants");
  for (size_t i = 0; i < grants->n; i++) {
    const Json *grant = grants->items[i];
    if (!grant_matches_scope(grant, product, product_family)) continue;
    if (string_list_contains(obj_get(grant, "features"), feature)) return 1;
    const Json *policy = obj_get(grant, "feature_policy");
    if (policy && policy->kind == J_STRING &&
        str_equals(policy->str, "published-through")) {
      if (published_at && window_allows(claims, "features_through", published_at)) {
        return 1;
      }
    }
  }
  return 0;
}

static int update_entitled(const Json *claims, const char *product,
                           const char *published_at, const char *at,
                           const char *product_family, const char *version,
                           const char *installation_id, const Json *activation,
                           const Json **extensions, size_t extension_n) {
  if (!base_policy_ok(claims, at, installation_id, activation, extensions,
                      extension_n, version)) return 0;
  const Json *grants = obj_get(claims, "grants");
  int matched = 0;
  for (size_t i = 0; i < grants->n && !matched; i++) {
    matched = grant_matches_scope(grants->items[i], product, product_family);
  }
  if (!matched) return 0;
  return window_allows(claims, "updates_through", published_at);
}

static int edition_entitled(const Json *claims, const char *product,
                            const char *edition, const char *at,
                            const char *product_family, const char *version,
                            const char *installation_id, const Json *activation,
                            const Json **extensions, size_t extension_n) {
  if (!base_policy_ok(claims, at, installation_id, activation, extensions,
                      extension_n, version)) return 0;
  const Json *grants = obj_get(claims, "grants");
  for (size_t i = 0; i < grants->n; i++) {
    const Json *grant = grants->items[i];
    if (!grant_matches_scope(grant, product, product_family)) continue;
    const Json *e = obj_get(grant, "edition");
    if (e && e->kind == J_STRING && str_equals(e->str, edition)) return 1;
  }
  return 0;
}

static int addon_entitled(const Json *claims, const char *product,
                          const char *addon, const char *at,
                          const char *product_family, const char *version,
                          const char *installation_id, const Json *activation,
                          const Json **extensions, size_t extension_n) {
  if (!base_policy_ok(claims, at, installation_id, activation, extensions,
                      extension_n, version)) return 0;
  const Json *grants = obj_get(claims, "grants");
  for (size_t i = 0; i < grants->n; i++) {
    const Json *grant = grants->items[i];
    if (!grant_matches_scope(grant, product, product_family)) continue;
    if (string_list_contains(obj_get(grant, "addons"), addon)) return 1;
  }
  return 0;
}

/* Scalar equality for conformance expectations: null, booleans, strings,
 * and numbers (an integer and a real compare by value). */
static int json_scalar_equals(const Json *a, const Json *b) {
  if (!a || !b) return 0;
  if (a->kind == J_NULL || b->kind == J_NULL) return a->kind == b->kind;
  if (a->kind == J_BOOL && b->kind == J_BOOL) return a->boolean == b->boolean;
  if (a->kind == J_STRING && b->kind == J_STRING) return str_equals(a->str, b->str);
  if ((a->kind == J_INT || a->kind == J_REAL) && (b->kind == J_INT || b->kind == J_REAL)) {
    double x = a->kind == J_INT ? (double)a->integer : a->real;
    double y = b->kind == J_INT ? (double)b->integer : b->real;
    return x == y;
  }
  return 0;
}

/* The capability value across matching grants, or NULL when none grants it.
 * Conflicting values fail closed: *conflict is set and NULL is returned. */
static const Json *capability_value(const Json *claims, const char *product,
                                    const char *name, const char *at,
                                    const char *product_family, const char *version,
                                    const char *installation_id, const Json *activation,
                                    const Json **extensions, size_t extension_n,
                                    int *conflict) {
  *conflict = 0;
  if (!base_policy_ok(claims, at, installation_id, activation, extensions,
                      extension_n, version)) return NULL;
  const Json *grants = obj_get(claims, "grants");
  const Json *found = NULL;
  for (size_t i = 0; i < grants->n; i++) {
    const Json *grant = grants->items[i];
    if (!grant_matches_scope(grant, product, product_family)) continue;
    const Json *v = obj_get(obj_get(grant, "capabilities"), name);
    if (!v) continue;
    if (found && !json_scalar_equals(found, v)) {
      *conflict = 1;
      return NULL;
    }
    found = v;
  }
  return found;
}

/* The named limit, or NULL when the credential sets none (JSON null). */
static const Json *limit_value(const Json *claims, const char *name, const char *at,
                               const char *version, const char *installation_id,
                               const Json *activation, const Json **extensions,
                               size_t extension_n) {
  if (!base_policy_ok(claims, at, installation_id, activation, extensions,
                      extension_n, version)) return NULL;
  const Json *v = obj_get(obj_get(obj_get(claims, "constraints"), "limits"), name);
  if (!v || v->kind == J_NULL) return NULL;
  return v;
}

/* Selects the newest statement of one entitlement lineage. Mirrors
 * select-latest-entitlement: every statement must be an entitlement or
 * trial of the same issuer and entitlement_id; the highest revision wins;
 * two different payloads at that revision fail closed. */
static Outcome select_latest(const Json **claims, const char **payloads, size_t n,
                             size_t *selected) {
  const char *entitlement_id = obj_get(claims[0], "entitlement_id")->str;
  const char *issuer = obj_get(claims[0], "issuer")->str;
  long long highest = -1;
  for (size_t i = 0; i < n; i++) {
    const char *type = obj_get(claims[i], "type")->str;
    if (!str_equals(type, "entitlement") && !str_equals(type, "trial")) {
      return ERR_LINEAGE_MISMATCH;
    }
    if (!str_equals(obj_get(claims[i], "entitlement_id")->str, entitlement_id) ||
        !str_equals(obj_get(claims[i], "issuer")->str, issuer)) {
      return ERR_LINEAGE_MISMATCH;
    }
    long long revision = obj_get(claims[i], "revision")->integer;
    if (revision > highest) highest = revision;
  }
  size_t first = n;
  for (size_t i = 0; i < n; i++) {
    if (obj_get(claims[i], "revision")->integer != highest) continue;
    if (first == n) {
      first = i;
    } else if (!str_equals(payloads[i], payloads[first])) {
      return ERR_LINEAGE_CONFLICT;
    }
  }
  *selected = first;
  return VERIFY_OK;
}

/* ------------------------------------------------------------------ */
/* Conformance driver                                                  */
/* ------------------------------------------------------------------ */

static char *path_join(const char *dir, const char *name) {
  size_t n = strlen(dir) + strlen(name) + 2;
  char *path = xmalloc(n);
  snprintf(path, n, "%s/%s", dir, name);
  return path;
}

static Json *load_json(const char *dir, const char *name) {
  char *path = path_join(dir, name);
  Bytes file = read_whole_file(path);
  free(path);
  if (!file.data) {
    fprintf(stderr, "error: %s\n", g_error);
    exit(2);
  }
  Json *v = json_parse_strict((const char *)file.data, file.len);
  bytes_free(&file);
  if (!v) {
    fprintf(stderr, "error parsing %s: %s\n", name, g_error);
    exit(2);
  }
  return v;
}

static int g_checks;
static int g_failures;

static void report(int ok, const char *fmt, ...) {
  g_checks++;
  va_list args;
  va_start(args, fmt);
  if (ok) {
    printf("[pass] ");
    vprintf(fmt, args);
    printf("\n");
  } else {
    g_failures++;
    printf("[FAIL] ");
    vprintf(fmt, args);
    printf(" -- %s\n", g_error[0] ? g_error : "(no detail)");
  }
  va_end(args);
}

/* Loads and validates a trust store; returns NULL (with g_error) on reject. */
static TrustStore *try_trust_store(const char *dir, const char *name) {
  char *path = path_join(dir, name);
  Bytes file = read_whole_file(path);
  free(path);
  if (!file.data) return NULL;
  Json *root = json_parse_strict((const char *)file.data, file.len);
  bytes_free(&file);
  if (!root) return NULL;
  TrustStore *store = trust_store_parse(root);
  json_free(root);
  return store;
}

static Outcome expect_outcome(const char *expected) {
  if (str_equals(expected, "verify")) return VERIFY_OK;
  if (str_equals(expected, "signature-reject")) return ERR_SIGNATURE;
  if (str_equals(expected, "unknown-key-reject")) return ERR_UNKNOWN_KEY;
  if (str_equals(expected, "revoked-key-reject")) return ERR_REVOKED_KEY;
  if (str_equals(expected, "issuance-window-reject")) return ERR_ISSUANCE_WINDOW;
  if (str_equals(expected, "key-purpose-reject")) return ERR_KEY_PURPOSE;
  if (str_equals(expected, "trust-store-reject")) return ERR_TRUST_STORE;
  if (str_equals(expected, "duplicate-json-reject")) return ERR_JSON_STRUCTURAL;
  if (str_equals(expected, "json-structural-reject")) return ERR_JSON_STRUCTURAL;
  if (str_equals(expected, "envelope-reject")) return ERR_ENVELOPE;
  if (str_equals(expected, "payload-reject")) return ERR_PAYLOAD;
  if (str_equals(expected, "issuer-mismatch-reject")) return ERR_ISSUER_MISMATCH;
  if (str_equals(expected, "lineage-conflict-reject")) return ERR_LINEAGE_CONFLICT;
  if (str_equals(expected, "lineage-mismatch-reject")) return ERR_LINEAGE_MISMATCH;
  return (Outcome)-1;
}

/* Verifies every positive credential in the byte-level manifest. */
static void run_manifest(const char *dir, const TrustStore *store) {
  Json *manifest = load_json(dir, "credential-vectors.json");
  const Json *protocol = obj_get(manifest, "protocol");
  report(protocol && protocol->kind == J_STRING &&
             str_equals(protocol->str, "permit-vector-manifest"),
         "manifest protocol is permit-vector-manifest");
  const Json *version = obj_get(manifest, "version");
  report(version && version->kind == J_INT && version->integer == 1,
         "manifest version is 1");
  const Json *manifest_key_id = obj_get(manifest, "key_id");
  const Json *entries = obj_get(manifest, "credentials");
  report(entries && entries->kind == J_ARRAY && entries->n == 5,
         "manifest lists five credentials");

  for (size_t i = 0; i < entries->n; i++) {
    const Json *entry = entries->items[i];
    const char *name = obj_get(entry, "name")->str;
    char *payload_path =
        path_join(dir, obj_get(entry, "payload_file")->str);
    char *credential_path =
        path_join(dir, obj_get(entry, "credential_file")->str);

    Bytes payload = read_whole_file(payload_path);
    report(payload.data != NULL, "%s: payload file readable", name);
    const Json *length_field = obj_get(entry, "payload_length");
    report(length_field && length_field->kind == J_INT &&
               length_field->integer == (long long)payload.len,
         "%s: payload length matches manifest", name);

    char hex[65];
    sha256_hex(payload.data, payload.len, hex);
    report(str_equals(hex, obj_get(entry, "payload_sha256_hex")->str),
           "%s: payload SHA-256 matches manifest", name);

    Outcome o = verify_credential_file(credential_path, store, NULL, NULL);
    report(o == VERIFY_OK, "%s: credential verifies", name);

    /* Byte-level binding: the envelope authenticates exactly these bytes. */
    Bytes file = read_whole_file(credential_path);
    Json *envelope = json_parse_strict((const char *)file.data, file.len);
    if (envelope) {
      Bytes envelope_payload = {NULL, 0};
      const Json *payload_field = obj_get(envelope, "payload");
      if (payload_field && payload_field->kind == J_STRING) {
        b64_decode(payload_field->str, strlen(payload_field->str), &envelope_payload);
      }
      report(envelope_payload.data && envelope_payload.len == payload.len &&
                 memcmp(envelope_payload.data, payload.data, payload.len) == 0,
             "%s: envelope authenticates the manifest payload bytes", name);
      report(str_equals(obj_get(envelope, "key_id")->str, manifest_key_id->str),
             "%s: envelope key_id matches manifest", name);
      report(str_equals(obj_get(envelope, "signature")->str,
                        obj_get(entry, "signature_base64")->str),
             "%s: envelope signature matches manifest", name);
      bytes_free(&envelope_payload);
      json_free(envelope);
    } else {
      report(0, "%s: envelope parses", name);
    }
    bytes_free(&file);
    bytes_free(&payload);
    free(payload_path);
    free(credential_path);
  }
  json_free(manifest);

  /*
   * Any payload-byte change invalidates the exact-byte signature. Mirrors
   * vector-test.rkt by appending one byte and expecting verification to
   * fail under the manifest signature.
   */
  {
    char *payload_path = path_join(dir, "entitlement-payload.json");
    Bytes payload = read_whole_file(payload_path);
    free(payload_path);
    report(payload.data != NULL, "exact-byte guard: payload readable");
    Bytes signature = {NULL, 0};
    char *credential_path = path_join(dir, "entitlement.permit.json");
    Bytes file = read_whole_file(credential_path);
    free(credential_path);
    Json *envelope = file.data
                         ? json_parse_strict((const char *)file.data, file.len)
                         : NULL;
    bytes_free(&file);
    if (envelope && payload.data) {
      const Json *sig_field = obj_get(envelope, "signature");
      const Json *key_id = obj_get(envelope, "key_id");
      if (sig_field && sig_field->kind == J_STRING &&
          b64_decode(sig_field->str, strlen(sig_field->str), &signature) == 0 &&
          key_id) {
        const TrustKey *key = trust_store_lookup(store, key_id->str);
        unsigned char *mutated = xmalloc(payload.len + 1);
        memcpy(mutated, payload.data, payload.len);
        mutated[payload.len] = ' ';
        report(key != NULL &&
                   ed25519_verify(key->raw_key, payload.data, payload.len,
                                  signature.data, signature.len) == 1 &&
                   ed25519_verify(key->raw_key, mutated, payload.len + 1,
                                  signature.data, signature.len) == 0,
               "exact-byte guard: one appended byte breaks the signature");
        free(mutated);
      } else {
        report(0, "exact-byte guard: envelope fields readable");
      }
    } else {
      report(0, "exact-byte guard: envelope parses");
    }
    json_free(envelope);
    bytes_free(&signature);
    bytes_free(&payload);
  }
}

/* Runs every case in conformance.json. */
static void run_conformance(const char *dir, const TrustStore *store) {
  Json *conformance = load_json(dir, "conformance.json");
  const Json *protocol = obj_get(conformance, "protocol");
  report(protocol && protocol->kind == J_STRING &&
             str_equals(protocol->str, "permit-conformance"),
         "conformance protocol is permit-conformance");
  const Json *version = obj_get(conformance, "version");
  report(version && version->kind == J_INT && version->integer == 1,
         "conformance version is 1");

  const Json *cases = obj_get(conformance, "cases");
  for (size_t c = 0; c < cases->n; c++) {
    const Json *tc = cases->items[c];
    const char *name = obj_get(tc, "name")->str;
    const Json *expected_field = obj_get(tc, "expected");
    const char *trust_store_name =
        obj_get(tc, "trust_store") ? obj_get(tc, "trust_store")->str : NULL;
    const Json *query = obj_get(tc, "query");

    g_error[0] = '\0';

    if (expected_field->kind == J_STRING &&
        str_equals(expected_field->str, "trust-store-reject")) {
      TrustStore *rejected = try_trust_store(dir, trust_store_name);
      int ok = rejected == NULL && strstr(g_error, "same public key") != NULL;
      trust_store_free(rejected);
      report(ok, "%s", name);
      continue;
    }
    if (expected_field->kind == J_STRING &&
        str_equals(expected_field->str, "duplicate-json-reject")) {
      char *path = path_join(dir, obj_get(tc, "credential")->str);
      Bytes file = read_whole_file(path);
      free(path);
      Json *envelope =
          file.data ? json_parse_strict((const char *)file.data, file.len) : NULL;
      bytes_free(&file);
      int ok = envelope == NULL && strstr(g_error, "duplicate JSON object member") != NULL;
      json_free(envelope);
      report(ok, "%s", name);
      continue;
    }
    if (expected_field->kind == J_STRING &&
        str_equals(expected_field->str, "json-structural-reject")) {
      /* Any strict-JSON structural failure: duplicate member, raw control
         character, invalid escape, or trailing bytes. The class stays
         distinct from envelope-shape rejection so both implementations
         report the same reason. */
      char *path = path_join(dir, obj_get(tc, "credential")->str);
      Bytes file = read_whole_file(path);
      free(path);
      Json *envelope =
          file.data ? json_parse_strict((const char *)file.data, file.len) : NULL;
      bytes_free(&file);
      int ok = envelope == NULL;
      json_free(envelope);
      report(ok, "%s", name);
      continue;
    }
    if (obj_get(tc, "credentials")) {
      /* Lineage: verify every statement, then select. */
      const Json *files = obj_get(tc, "credentials");
      enum { MAX_LINEAGE = 8 };
      const Json *lineage_claims[MAX_LINEAGE];
      const char *lineage_payloads[MAX_LINEAGE];
      Json *lineage_envelopes[MAX_LINEAGE] = {0};
      size_t lineage_n = 0;
      Outcome o = VERIFY_OK;
      TrustStore *fresh_store = try_trust_store(dir, trust_store_name);
      const TrustStore *case_store = fresh_store ? fresh_store : store;
      for (size_t i = 0; i < files->n && i < MAX_LINEAGE && o == VERIFY_OK; i++) {
        char *path = path_join(dir, files->items[i]->str);
        const Json *claims = NULL;
        o = verify_credential_file(path, case_store, &claims, &lineage_envelopes[i]);
        free(path);
        if (o == VERIFY_OK) {
          lineage_claims[lineage_n] = claims;
          lineage_payloads[lineage_n] = obj_get(lineage_envelopes[i], "payload")->str;
          lineage_n++;
        }
      }
      size_t selected = 0;
      if (o == VERIFY_OK) o = select_latest(lineage_claims, lineage_payloads, lineage_n, &selected);
      if (expected_field->kind == J_STRING) {
        Outcome want = expect_outcome(expected_field->str);
        report(o == want, "%s (want %s, got %s)", name, outcome_name(want), outcome_name(o));
      } else {
        const char *selects = obj_get(query, "selects")->str;
        int ok = o == VERIFY_OK &&
                 str_equals(obj_get(lineage_claims[selected], "credential_id")->str, selects);
        report(ok == expected_field->boolean, "%s", name);
      }
      for (size_t i = 0; i < MAX_LINEAGE; i++) json_free(lineage_envelopes[i]);
      trust_store_free(fresh_store);
      continue;
    }

    const TrustStore *case_store = store;
    TrustStore *fresh_store = NULL;
    if (trust_store_name && !str_equals(trust_store_name, "trust-store.json")) {
      /* Policy cases always use the default store; a different store here
       * would be a rejection case handled above. */
      fresh_store = try_trust_store(dir, trust_store_name);
      case_store = fresh_store;
      if (!case_store) {
        report(0, "%s (trust store failed to load)", name);
        continue;
      }
    }

    char credential_path_buf[512];
    {
      char *p = path_join(dir, obj_get(tc, "credential")->str);
      snprintf(credential_path_buf, sizeof(credential_path_buf), "%s", p);
      free(p);
    }

    const Json *claims = NULL;
    Json *envelope = NULL;
    Json *activation_envelope = NULL;
    Json *extension_envelopes[MAX_EXTENSIONS] = {0};
    Outcome o = verify_credential_file(credential_path_buf, case_store, &claims,
                                       &envelope);

    if (expected_field->kind == J_STRING) {
      Outcome want = expect_outcome(expected_field->str);
      int ok = o == want;
      /* Unknown key ids must reject before the payload is even authorized,
       * so both the class and the message have to line up. */
      if (ok && want == VERIFY_OK && claims == NULL) ok = 0;
      report(ok, "%s (want %s, got %s)", name, outcome_name(want), outcome_name(o));
    } else {
      /* Boolean policy expectation. */
      if (o != VERIFY_OK) {
        report(0, "%s (credential unexpectedly rejected: %s)", name,
               outcome_name(o));
      } else {
        const char *at = obj_get(query, "at") ? obj_get(query, "at")->str : NULL;
        const char *kind = obj_get(query, "kind")->str;
        const char *installation_id = obj_get(query, "installation_id")
                                          ? obj_get(query, "installation_id")->str
                                          : NULL;
        const char *published_at = obj_get(query, "published_at")
                                       ? obj_get(query, "published_at")->str
                                       : NULL;
        const char *query_version = obj_get(query, "version")
                                        ? obj_get(query, "version")->str
                                        : NULL;
        if ((at && !time_valid(at)) || (published_at && !time_valid(published_at)) ||
            (query_version && !semver_parse(query_version, &(SemVer){0}))) {
          fprintf(stderr, "malformed conformance query in case %s\n", name);
          exit(2);
        }
        const Json *activation_claims = NULL;
        if (obj_get(tc, "activation")) {
          char *p = path_join(dir, obj_get(tc, "activation")->str);
          Outcome ao = verify_credential_file(p, case_store, &activation_claims,
                                              &activation_envelope);
          free(p);
          if (ao != VERIFY_OK) {
            report(0, "%s (activation credential rejected: %s)", name,
                   outcome_name(ao));
            goto next_case;
          }
        }
        const Json *extensions[MAX_EXTENSIONS];
        size_t extension_n = 0;
        const Json *extension_list = obj_get(tc, "trial_extensions");
        if (extension_list) {
          int broken = 0;
          for (size_t i = 0; i < extension_list->n; i++) {
            char *p = path_join(dir, extension_list->items[i]->str);
            const Json *ext_claims = NULL;
            Json *ext_envelope = NULL;
            Outcome eo = verify_credential_file(p, case_store, &ext_claims,
                                                &ext_envelope);
            free(p);
            if (eo != VERIFY_OK || extension_n >= MAX_EXTENSIONS) {
              json_free(ext_envelope);
              report(0, "%s (trial extension rejected: %s)", name, outcome_name(eo));
              broken = 1;
              break;
            }
            extensions[extension_n] = ext_claims;
            extension_envelopes[extension_n++] = ext_envelope;
          }
          if (broken) goto next_case;
        }

        int actual = 0;
        int evaluated = 1;
        if (str_equals(kind, "usable")) {
          CredentialStatus status = credential_status(
              claims, at, installation_id, activation_claims, extensions, extension_n);
          actual = status.usable;
          const Json *expected_reasons = obj_get(tc, "expected_reasons");
          if (expected_reasons) {
            int reasons_ok = status.reason_n == expected_reasons->n;
            for (size_t i = 0; reasons_ok && i < status.reason_n; i++) {
              reasons_ok = str_equals(status.reasons[i],
                                      expected_reasons->items[i]->str);
            }
            if (!reasons_ok) {
              printf("         reasons: [");
              for (size_t i = 0; i < status.reason_n; i++) {
                printf("%s%s", i ? ", " : "", status.reasons[i]);
              }
              printf("]\n");
            }
            evaluated = reasons_ok;
          }
        } else if (str_equals(kind, "feature")) {
          actual = feature_entitled(
              claims, obj_get(query, "product")->str, obj_get(query, "feature")->str,
              obj_get(query, "published_at") ? obj_get(query, "published_at")->str
                                             : NULL,
              at, NULL, obj_get(query, "version") ? obj_get(query, "version")->str
                                                  : NULL,
              installation_id, activation_claims, extensions, extension_n);
        } else if (str_equals(kind, "update")) {
          actual = update_entitled(
              claims, obj_get(query, "product")->str,
              obj_get(query, "published_at")->str, at, NULL,
              obj_get(query, "version") ? obj_get(query, "version")->str : NULL,
              installation_id, activation_claims, extensions, extension_n);
        } else if (str_equals(kind, "version")) {
          actual = version_policy_allowed(claims, obj_get(query, "version")->str);
        } else if (str_equals(kind, "edition")) {
          actual = edition_entitled(
              claims, obj_get(query, "product")->str, obj_get(query, "edition")->str, at,
              obj_get(query, "product_family") ? obj_get(query, "product_family")->str : NULL,
              obj_get(query, "version") ? obj_get(query, "version")->str : NULL,
              installation_id, activation_claims, extensions, extension_n);
        } else if (str_equals(kind, "addon")) {
          actual = addon_entitled(
              claims, obj_get(query, "product")->str, obj_get(query, "addon")->str, at,
              obj_get(query, "product_family") ? obj_get(query, "product_family")->str : NULL,
              obj_get(query, "version") ? obj_get(query, "version")->str : NULL,
              installation_id, activation_claims, extensions, extension_n);
        } else if (str_equals(kind, "capability")) {
          /* equals is a JSON scalar; a missing capability compares as null */
          int conflict = 0;
          const Json *value = capability_value(
              claims, obj_get(query, "product")->str, obj_get(query, "name")->str, at,
              obj_get(query, "product_family") ? obj_get(query, "product_family")->str : NULL,
              obj_get(query, "version") ? obj_get(query, "version")->str : NULL,
              installation_id, activation_claims, extensions, extension_n, &conflict);
          const Json *equals = obj_get(query, "equals");
          if (conflict) {
            actual = 0;
            evaluated = 0;
            printf("         capability values conflict across grants\n");
          } else if (!value) {
            actual = equals && equals->kind == J_NULL;
          } else {
            actual = json_scalar_equals(value, equals);
          }
        } else if (str_equals(kind, "limit")) {
          const Json *value = limit_value(
              claims, obj_get(query, "name")->str, at,
              obj_get(query, "version") ? obj_get(query, "version")->str : NULL,
              installation_id, activation_claims, extensions, extension_n);
          const Json *equals = obj_get(query, "equals");
          actual = value ? json_scalar_equals(value, equals)
                         : (equals && equals->kind == J_NULL);
        } else {
          fprintf(stderr, "unknown conformance query kind: %s\n", kind);
          exit(2);
        }
        int want = expected_field->boolean;
        report(actual == want && evaluated, "%s", name);
      }
    }
  next_case:;
    trust_store_free(fresh_store);
    json_free(envelope);
    json_free(activation_envelope);
    for (size_t i = 0; i < MAX_EXTENSIONS; i++) {
      json_free(extension_envelopes[i]);
    }
  }
  json_free(conformance);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: permit-conformance <test-vectors/v1 directory>\n");
    return 2;
  }
  const char *dir = argv[1];

  TrustStore *store = try_trust_store(dir, "trust-store.json");
  if (!store) {
    fprintf(stderr, "error: default trust store failed: %s\n", g_error);
    return 2;
  }

  printf("Permit Protocol v1 conformance runner (C)\n");
  printf("corpus: %s\n\n", dir);

  run_manifest(dir, store);
  printf("\n");
  run_conformance(dir, store);

  printf("\n%d checks, %d failures\n", g_checks, g_failures);
  trust_store_free(store);
  return g_failures == 0 ? 0 : 1;
}
