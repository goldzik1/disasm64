#include "disasm64/image.h"
#include <cstring>

namespace disasm64 {
namespace {

struct ImgView {
    const uint8_t* p; size_t n;
    uint16_t u16(size_t o) const { return o + 2 <= n ? uint16_t(p[o] | (p[o + 1] << 8)) : 0; }
    uint32_t u32(size_t o) const {
        return o + 4 <= n ? uint32_t(p[o]) | (uint32_t(p[o + 1]) << 8) | (uint32_t(p[o + 2]) << 16) | (uint32_t(p[o + 3]) << 24) : 0;
    }
    uint64_t u64(size_t o) const { return uint64_t(u32(o)) | (uint64_t(u32(o + 4)) << 32); }
};

// Read a NUL-terminated string at a virtual address.
std::string cstrAt(const LoadedImage& im, uint64_t va) {
    size_t off = vaToOffset(im, va);
    if (off == SIZE_MAX) return {};
    size_t max = im.file.size() - off;
    const char* s = reinterpret_cast<const char*>(im.file.data() + off);
    return std::string(s, ::strnlen(s, max));
}

bool printable(uint8_t c) { return c >= 0x20 && c <= 0x7E; }

} // namespace

std::vector<Import> parseImports(const LoadedImage& im) {
    std::vector<Import> out;
    if (!im.isPE || !im.importRva) return out;
    bool pe32plus = im.format == "PE32+";
    int ptr = pe32plus ? 8 : 4;
    uint64_t ordFlag = pe32plus ? 0x8000000000000000ull : 0x80000000ull;
    ImgView v{im.file.data(), im.file.size()};

    for (uint32_t d = 0;; d += 20) {
        size_t desc = vaToOffset(im, im.imageBase + im.importRva + d);
        if (desc == SIZE_MAX) break;
        uint32_t iltRva = v.u32(desc);
        uint32_t nameRva = v.u32(desc + 12);
        uint32_t iatRva = v.u32(desc + 16);
        if (!nameRva && !iatRva && !iltRva) break;
        std::string dll = cstrAt(im, im.imageBase + nameRva);
        uint32_t walkRva = iltRva ? iltRva : iatRva;
        for (uint32_t i = 0;; ++i) {
            size_t th = vaToOffset(im, im.imageBase + walkRva + i * ptr);
            if (th == SIZE_MAX) break;
            uint64_t thunk = pe32plus ? v.u64(th) : v.u32(th);
            if (!thunk) break;
            Import imp;
            imp.dll = dll;
            imp.iatVa = im.imageBase + iatRva + uint64_t(i) * ptr;
            if (thunk & ordFlag) imp.ordinal = uint16_t(thunk & 0xFFFF);
            else imp.name = cstrAt(im, im.imageBase + uint32_t(thunk) + 2);   // skip the hint word
            out.push_back(std::move(imp));
            if (out.size() > 100000) return out;
        }
    }
    return out;
}

std::vector<Export> parseExports(const LoadedImage& im) {
    std::vector<Export> out;
    if (!im.isPE || !im.exportRva) return out;
    ImgView v{im.file.data(), im.file.size()};
    size_t dir = vaToOffset(im, im.imageBase + im.exportRva);
    if (dir == SIZE_MAX) return out;
    uint32_t ordBase = v.u32(dir + 16);
    uint32_t nFuncs = v.u32(dir + 20);
    uint32_t nNames = v.u32(dir + 24);
    uint32_t funcsRva = v.u32(dir + 28);
    uint32_t namesRva = v.u32(dir + 32);
    uint32_t ordsRva = v.u32(dir + 36);
    if (nNames > 1000000 || nFuncs > 1000000) return out;

    for (uint32_t i = 0; i < nNames; ++i) {
        size_t namePtr = vaToOffset(im, im.imageBase + namesRva + i * 4);
        size_t ordPtr = vaToOffset(im, im.imageBase + ordsRva + i * 2);
        if (namePtr == SIZE_MAX || ordPtr == SIZE_MAX) break;
        uint32_t nameRva = v.u32(namePtr);
        uint16_t ord = v.u16(ordPtr);
        if (ord >= nFuncs) continue;
        size_t fnPtr = vaToOffset(im, im.imageBase + funcsRva + uint32_t(ord) * 4);
        if (fnPtr == SIZE_MAX) continue;
        uint32_t fnRva = v.u32(fnPtr);
        Export e;
        e.name = cstrAt(im, im.imageBase + nameRva);
        e.va = fnRva ? im.imageBase + fnRva : 0;
        e.ordinal = ordBase + ord;
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<FoundString> findStrings(const LoadedImage& im, size_t minLen) {
    std::vector<FoundString> out;
    const uint8_t* base = im.file.data();
    for (const Section& s : im.sections) {
        if (s.exec) continue;   // strings live in data sections; code produces only noise
        const uint8_t* d = base + s.fileOffset;
        size_t n = s.rawSize;
        for (size_t i = 0; i < n;) {
            // ASCII run
            size_t j = i;
            while (j < n && printable(d[j])) ++j;
            if (j - i >= minLen) {
                FoundString fs;
                fs.va = s.vaddr + i;
                fs.text.assign(reinterpret_cast<const char*>(d + i), j - i);
                out.push_back(std::move(fs));
                i = j;
                continue;
            }
            // UTF-16LE run (char, 0x00 pairs)
            size_t k = i, cnt = 0;
            std::string w;
            while (k + 1 < n && printable(d[k]) && d[k + 1] == 0) { w += char(d[k]); k += 2; ++cnt; }
            if (cnt >= minLen) {
                FoundString fs; fs.va = s.vaddr + i; fs.text = std::move(w); fs.wide = true;
                out.push_back(std::move(fs));
                i = k;
                continue;
            }
            ++i;
        }
        if (out.size() > 200000) break;
    }
    return out;
}

std::vector<Match> patternSearch(const LoadedImage& im, const std::string& pattern) {
    std::vector<Match> out;
    std::vector<uint8_t> bytes;
    std::vector<bool> wild;
    for (size_t i = 0; i < pattern.size();) {
        char c = pattern[i];
        if (c == ' ') { ++i; continue; }
        if (c == '?') { wild.push_back(true); bytes.push_back(0); while (i < pattern.size() && pattern[i] == '?') ++i; continue; }
        auto hv = [](char x) -> int {
            if (x >= '0' && x <= '9') return x - '0';
            if (x >= 'a' && x <= 'f') return x - 'a' + 10;
            if (x >= 'A' && x <= 'F') return x - 'A' + 10;
            return -1;
        };
        int hi = hv(c);
        if (hi < 0 || i + 1 >= pattern.size()) return out;   // malformed
        int lo = hv(pattern[i + 1]);
        if (lo < 0) return out;
        bytes.push_back(uint8_t(hi * 16 + lo)); wild.push_back(false);
        i += 2;
    }
    if (bytes.empty()) return out;

    const uint8_t* fb = im.file.data();
    for (const Section& s : im.sections) {
        const uint8_t* d = fb + s.fileOffset;
        size_t n = s.rawSize;
        if (n < bytes.size()) continue;
        for (size_t i = 0; i + bytes.size() <= n; ++i) {
            bool hit = true;
            for (size_t j = 0; j < bytes.size(); ++j)
                if (!wild[j] && d[i + j] != bytes[j]) { hit = false; break; }
            if (hit) {
                out.push_back({s.vaddr + i, s.fileOffset + i});
                if (out.size() > 100000) return out;
            }
        }
    }
    return out;
}

bool applyPatch(LoadedImage& im, uint64_t va, const uint8_t* bytes, size_t n) {
    size_t off = vaToOffset(im, va);
    if (off == SIZE_MAX || off + n > im.file.size()) return false;
    std::memcpy(im.file.data() + off, bytes, n);
    return true;
}

} // namespace disasm64
