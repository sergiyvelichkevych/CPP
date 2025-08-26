// Build this TU **without** instrumentation (see commands below).
// GNU/Linux + GCC, C++17+.

#define _GNU_SOURCE
#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <dlfcn.h>          // dladdr
#include <cxxabi.h>         // abi::__cxa_demangle

// Mark all helpers as non-instrumented to avoid recursion.
#define NOINST __attribute__((no_instrument_function))

struct NOINST Frame {
    void* fn;
    uint64_t start_ns;
    uint64_t child_ns;
};

struct NOINST Agg {
    uint64_t calls = 0;
    uint64_t incl_ns = 0;
    uint64_t excl_ns = 0;
    uint64_t max_incl_ns = 0;
};

struct NOINST ThreadData {
    std::vector<Frame> stack;
    std::unordered_map<void*, Agg> local;
    void flush_to_global();
    ~ThreadData(); // defined below with NOINST
};

static std::mutex g_mu NOINST;
static std::unordered_map<void*, Agg> g_stats NOINST;

// Each thread accumulates locally (no locks on the hot path) and merges at exit.
static thread_local ThreadData tdata;
static thread_local int tls_guard NOINST = 0; // reentrancy guard

// --- util ---
static inline uint64_t NOINST now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

void NOINST ThreadData::flush_to_global() {
    if (local.empty()) return;
    std::lock_guard<std::mutex> lk(g_mu);
    for (auto &kv : local) {
        auto &dst = g_stats[kv.first];
        dst.calls       += kv.second.calls;
        dst.incl_ns     += kv.second.incl_ns;
        dst.excl_ns     += kv.second.excl_ns;
        if (kv.second.max_incl_ns > dst.max_incl_ns) dst.max_incl_ns = kv.second.max_incl_ns;
    }
    local.clear();
}

ThreadData::~ThreadData() NOINST { flush_to_global(); }

// --- reporting ---
struct NOINST Row {
    void* fn;
    Agg a;
};

static const char* NOINST demangle(const char* name) {
    int status = 0;
    char* dem = abi::__cxa_demangle(name, nullptr, nullptr, &status);
    if (status == 0 && dem) return dem; // caller frees
    return nullptr;
}

static std::string NOINST addr_to_name(void* addr, std::string* module_out) {
    Dl_info info{};
    if (dladdr(addr, &info) && info.dli_sname) {
        const char* mod = info.dli_fname ? info.dli_fname : "";
        if (module_out) *module_out = mod;
        const char* pretty = demangle(info.dli_sname);
        if (pretty) {
            std::string s(pretty);
            std::free((void*)pretty);
            return s;
        }
        return info.dli_sname;
    }
    if (module_out) module_out->clear();
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%p", addr);
    return buf;
}

static void NOINST write_report() {
    // Ensure main thread data is merged.
    tdata.flush_to_global();

    // Snapshot + sort by total exclusive time.
    std::vector<Row> rows;
    rows.reserve(g_stats.size());
    {
        std::lock_guard<std::mutex> lk(g_mu);
        for (auto &kv : g_stats) rows.push_back({kv.first, kv.second});
    }
    std::sort(rows.begin(), rows.end(),
              [](const Row& x, const Row& y) { return x.a.excl_ns > y.a.excl_ns; });

    // Output: CSV to file or stderr
    const char* path = std::getenv("FPROF_OUT");
    FILE* out = path ? std::fopen(path, "w") : stderr;
    if (!out) out = stderr;

    std::fprintf(out, "module,function,calls,total_inclusive_ns,total_exclusive_ns,avg_inclusive_ns,avg_exclusive_ns,max_inclusive_ns\n");

    for (const auto& r : rows) {
        double avg_incl = r.a.calls ? (double)r.a.incl_ns / r.a.calls : 0.0;
        double avg_excl = r.a.calls ? (double)r.a.excl_ns / r.a.calls : 0.0;
        std::string module;
        std::string name = addr_to_name(r.fn, &module);
        // Escape basic CSV characters in name/module.
        auto esc = [](const std::string& s) -> std::string {
            bool need = s.find_first_of(",\"\n") != std::string::npos;
            if (!need) return s;
            std::string t = "\"";
            for (char c : s) t += (c == '\"') ? "\"\"" : std::string(1, c);
            t += "\"";
            return t;
        };
        std::fprintf(out, "%s,%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.0f,%.0f,%" PRIu64 "\n",
                     esc(module).c_str(), esc(name).c_str(),
                     r.a.calls, r.a.incl_ns, r.a.excl_ns,
                     avg_incl, avg_excl, r.a.max_incl_ns);
    }
    if (out != stderr) std::fclose(out);
}

// Register report at process exit.
static void NOINST at_exit_report() { write_report(); }
__attribute__((constructor)) static void NOINST init_prof() {
    std::atexit(at_exit_report); // atexit handler is non-instrumented (NOINST)
}

// --- instrumentation callbacks (C linkage) ---
extern "C" void __cyg_profile_func_enter(void* this_fn, void* /*call_site*/) NOINST;
extern "C" void __cyg_profile_func_exit (void* this_fn, void* /*call_site*/) NOINST;

// Guarded because we call into libstdc++/libc here and we *really* don't want recursion.
extern "C" void NOINST __cyg_profile_func_enter(void* this_fn, void*) {
    if (++tls_guard != 1) { --tls_guard; return; }
    uint64_t t = now_ns();
    tdata.stack.push_back(Frame{this_fn, t, 0});
    --tls_guard;
}

extern "C" void NOINST __cyg_profile_func_exit(void* this_fn, void*) {
    if (++tls_guard != 1) { --tls_guard; return; }

    uint64_t t = now_ns();

    // Pop the frame; handle rare mismatches (e.g., throws that skip the immediate exit).
    // In practice, __cyg_profile_func_exit might not be emitted for the function *throwing*
    // the exception; we reconcile by draining frames until we find a matching 'this_fn'.
    // (This keeps the stack consistent; timings of the throwing frame may be skewed.)
    while (!tdata.stack.empty()) {
        Frame fr = tdata.stack.back();
        tdata.stack.pop_back();

        uint64_t incl = t - fr.start_ns;
        uint64_t excl = (incl > fr.child_ns) ? (incl - fr.child_ns) : 0;

        Agg& a = tdata.local[fr.fn];
        a.calls++;
        a.incl_ns += incl;
        a.excl_ns += excl;
        if (incl > a.max_incl_ns) a.max_incl_ns = incl;

        // Attribute inclusive time to parent as "child time".
        if (!tdata.stack.empty()) {
            tdata.stack.back().child_ns += incl;
        }

        if (fr.fn == this_fn) break; // normal case; or we caught up after unwind
        // else: keep draining until we reconcile the stack.
    }

    --tls_guard;
}
