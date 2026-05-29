#include "re2_c_api.h"

#include <new>

#include <re2/re2.h>

struct ss_re2_regex {
    RE2 inner;

    explicit ss_re2_regex(const re2::StringPiece &pattern, const RE2::Options &options)
        : inner(pattern, options) {}
};

extern "C" ss_re2_regex *ss_re2_compile(const char *pattern, size_t pattern_len) {
    RE2::Options options;
    options.set_log_errors(false);
    auto *regex = new (std::nothrow) ss_re2_regex(re2::StringPiece(pattern, pattern_len), options);
    if (regex == nullptr) return nullptr;
    if (!regex->inner.ok()) {
        delete regex;
        return nullptr;
    }
    return regex;
}

extern "C" int ss_re2_partial_match(const ss_re2_regex *regex, const char *text, size_t text_len) {
    if (regex == nullptr) return 0;
    return RE2::PartialMatch(re2::StringPiece(text, text_len), regex->inner) ? 1 : 0;
}

extern "C" void ss_re2_destroy(ss_re2_regex *regex) {
    delete regex;
}
