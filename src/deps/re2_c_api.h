#ifndef SS_ZIG_RE2_C_API_H
#define SS_ZIG_RE2_C_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ss_re2_regex ss_re2_regex;

ss_re2_regex *ss_re2_compile(const char *pattern, size_t pattern_len);
int ss_re2_partial_match(const ss_re2_regex *regex, const char *text, size_t text_len);
void ss_re2_destroy(ss_re2_regex *regex);

#ifdef __cplusplus
}
#endif

#endif
