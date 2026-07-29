#pragma once
#include <cstdio>

inline int g_check_failures = 0;

#define CHECK(cond) do { if (!(cond)) { \
    std::printf("CHECK failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
    ++g_check_failures; } } while (0)

#define CHECK_EQ(a, b) do { auto _va = (a); auto _vb = (b); if (!(_va == _vb)) { \
    std::printf("CHECK_EQ failed: %s == %s (%s:%d)\n", #a, #b, __FILE__, __LINE__); \
    ++g_check_failures; } } while (0)

#define CHECK_STR(a, b) do { std::string _sa = (a); std::string _sb = (b); if (_sa != _sb) { \
    std::printf("CHECK_STR failed (%s:%d): got \"%s\" want \"%s\"\n", __FILE__, __LINE__, _sa.c_str(), _sb.c_str()); \
    ++g_check_failures; } } while (0)

#define TEST_MAIN(...) int main() { __VA_ARGS__ \
    if (g_check_failures) { std::printf("FAILED: %d\n", g_check_failures); return 1; } \
    std::printf("OK\n"); return 0; }
