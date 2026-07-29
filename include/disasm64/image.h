#pragma once
#include "loader.h"
#include <cstdint>
#include <string>
#include <vector>

namespace disasm64 {

struct Import {
    std::string dll;
    std::string name;     // empty when imported by ordinal
    uint16_t ordinal = 0;
    uint64_t iatVa = 0;   // slot in the import address table
};

struct Export {
    std::string name;
    uint64_t va = 0;
    uint32_t ordinal = 0;
};

struct FoundString {
    uint64_t va = 0;
    std::string text;
    bool wide = false;    // UTF-16LE
};

struct Match {
    uint64_t va = 0;
    size_t fileOffset = 0;
};

// PE import / export tables (empty for non-PE or when the directory is absent).
std::vector<Import> parseImports(const LoadedImage& im);
std::vector<Export> parseExports(const LoadedImage& im);

// Printable ASCII and UTF-16LE runs of at least minLen, with their virtual addresses.
std::vector<FoundString> findStrings(const LoadedImage& im, size_t minLen = 4);

// IDA-style byte-pattern search over the mapped sections. "?" / "??" are wildcard bytes,
// e.g. "48 8B ?? C0". Returns every match's address.
std::vector<Match> patternSearch(const LoadedImage& im, const std::string& pattern);

} // namespace disasm64
