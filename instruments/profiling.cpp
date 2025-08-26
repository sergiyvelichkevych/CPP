// prof_log_fast.cpp
// GCC + Linux. Build THIS file with: -O2 -std=c++17 -fno-instrument-functions
// Then build your app with: -finstrument-functions (see commands below).

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// --- attributes / macros ---
#define NOINST __attribute__((no_instrument_function))

// --- config via env vars ---
// FPROF_DIR: directory for logs (default: /tmp/fprof-<pid>)
// FPROF_UNBUFFERED=1: disable TLS buffer (one write() per event; slower but truly no buffering)
static char g_dir[PATH_MAX] = {0};
static pid_t g_pid = 0;
static int   g_unbuffered = 0;

static inline uint64_t NOINST now_ns() {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static inline pid_t NOINST get_tid() {
#ifdef SYS_gettid
    return (pid_t)syscall(SYS_gettid);
#else
    return (pid_t)getpid(); // fallback
#endif
}

static int NOINST make_dir_if_needed(const char* path, mode_t mode) {
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST)       return 0;
    return -1;
}

static int NOINST copy_file(const char* src, const char* dst) {
    int s = open(src, O_RDONLY | O_CLOEXEC);
    if (s < 0) return -1;
    int d = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (d < 0) { close(s); return -1; }
    char buf[8192];
    for (;;) {
        ssize_t r = read(s, buf, sizeof buf);
        if (r == 0) break;
        if (r < 0) { if (errno == EINTR) continue; close(s); close(d); return -1; }
        char* p = buf;
        ssize_t n = r;
        while (n > 0) {
            ssize_t w = write(d, p, (size_t)n);
            if (w < 0) { if (errno == EINTR) continue; close(s); close(d); return -1; }
            p += w; n -= w;
        }
    }
    close(s); close(d); return 0;
}

static ssize_t NOINST full_write(int fd, const void* data, size_t len) {
    const char* p = (const char*)data;
    size_t n = len;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return (ssize_t)len;
}

// --- Log format ---
struct NOINST LogHeader {
    char     magic[8];   // "FPROFv1"
    uint32_t pid;
    uint32_t tid;
    uint64_t start_ns;   // time when this file was opened
    uint32_t rec_size;   // sizeof(Record)
    uint32_t flags;      // bit0: MONOTONIC_RAW used (when available)
};
struct NOINST Record {
    uint64_t ts_ns;      // event timestamp (monotonic ns)
    uintptr_t fn;        // function address
    uint8_t  type;       // 0=enter, 1=exit
    uint8_t  pad[7];     // keep 24 bytes total
} __attribute__((packed));
static_assert(sizeof(Record) == 24, "Record size must be 24 bytes");

// --- TLS logger per thread ---
struct NOINST ThreadLogger {
    int      fd;
    size_t   pos;
    pid_t    tid;
    uint64_t opened_ns;
    enum { BUF_CAP = 64 * 1024 }; // per-thread buffer (set FPROF_UNBUFFERED=1 to disable)
    alignas(8) unsigned char buf[BUF_CAP];
    int      initialized;
    int      disabled;

    void ensure_init();
    void write_header();
    void flush();
    void append(const Record& r);
    ~ThreadLogger();
};

static thread_local ThreadLogger tlog;
static thread_local int tls_guard NOINST = 0;

// --- Implementation ---
void NOINST ThreadLogger::write_header() {
    LogHeader h{};
    memcpy(h.magic, "FPROFv1", 8);
    h.pid = (uint32_t)g_pid;
    h.tid = (uint32_t)tid;
    h.start_ns = opened_ns;
    h.rec_size = (uint32_t)sizeof(Record);
#ifdef CLOCK_MONOTONIC_RAW
    h.flags = 1u; // bit0 = MONOTONIC_RAW
#else
    h.flags = 0u;
#endif
    (void)full_write(fd, &h, sizeof h);
}

void NOINST ThreadLogger::ensure_init() {
    if (initialized || disabled) return;
    tid = get_tid();
    char path[PATH_MAX];
    // One file per thread: <dir>/<pid>.<tid>.bin
    int n = snprintf(path, sizeof path, "%s/%u.%u.bin", g_dir, (unsigned)g_pid, (unsigned)tid);
    if (n <= 0 || n >= (int)sizeof(path)) { disabled = 1; return; }

    // Create directory if someone called us before the constructor ran.
    (void)make_dir_if_needed(g_dir, 0755);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) { disabled = 1; return; }
    pos = 0;
    opened_ns = now_ns();
    write_header();
    initialized = 1;
}

void NOINST ThreadLogger::flush() {
    if (disabled || !initialized) return;
    if (pos == 0) return;
    (void)full_write(fd, buf, pos);
    pos = 0;
}

void NOINST ThreadLogger::append(const Record& r) {
    if (disabled) return;
    if (!initialized) ensure_init();
    if (disabled || fd < 0) return;

    if (g_unbuffered) {
        (void)full_write(fd, &r, sizeof r);
        return;
    }

    if (pos + sizeof(Record) > BUF_CAP) flush();
    memcpy(buf + pos, &r, sizeof r);
    pos += sizeof(Record);
}

ThreadLogger::~ThreadLogger() NOINST {
    if (initialized && !disabled) {
        flush();
        if (fd >= 0) close(fd);
    }
}

// --- process-wide init: set directory, dump maps/cmdline for offline symbolization ---
__attribute__((constructor))
static void NOINST fprof_init() {
    g_pid = getpid();

    const char* env_dir = getenv("FPROF_DIR");
    if (env_dir && env_dir[0]) {
        // Use given directory as-is
        snprintf(g_dir, sizeof g_dir, "%s", env_dir);
    } else {
        // Default: /tmp/fprof-<pid>
        snprintf(g_dir, sizeof g_dir, "/tmp/fprof-%u", (unsigned)g_pid);
    }
    (void)make_dir_if_needed(g_dir, 0755);

    const char* env_unbuf = getenv("FPROF_UNBUFFERED");
    g_unbuffered = (env_unbuf && env_unbuf[0] == '1') ? 1 : 0;

    // Save /proc/self/maps for the analyzer (address -> module resolution).
    char maps_path[PATH_MAX], cmd_path[PATH_MAX], exe_path[PATH_MAX], exe_out[PATH_MAX];
    snprintf(maps_path, sizeof maps_path, "%s/%u.maps", g_dir, (unsigned)g_pid);
    snprintf(cmd_path,  sizeof cmd_path,  "%s/%u.cmdline", g_dir, (unsigned)g_pid);
    snprintf(exe_out,   sizeof exe_out,   "%s/%u.exe", g_dir, (unsigned)g_pid);
    (void)copy_file("/proc/self/maps", maps_path);
    (void)copy_file("/proc/self/cmdline", cmd_path);
    // Resolve executable path
    ssize_t r = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (r > 0) { exe_path[r] = 0;
        int fd = open(exe_out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0) { (void)full_write(fd, exe_path, (size_t)r); close(fd); }
    }
}

// --- instrumentation hooks (called by GCC) ---
extern "C" void __cyg_profile_func_enter(void* this_fn, void* call_site) NOINST;
extern "C" void __cyg_profile_func_exit (void* this_fn, void* call_site) NOINST;

extern "C" void NOINST __cyg_profile_func_enter(void* this_fn, void*) {
    if (++tls_guard != 1) { --tls_guard; return; }
    Record rec;
    rec.ts_ns = now_ns();
    rec.fn    = (uintptr_t)this_fn;
    rec.type  = 0; // enter
    tlog.append(rec);
    --tls_guard;
}

extern "C" void NOINST __cyg_profile_func_exit(void* this_fn, void*) {
    if (++tls_guard != 1) { --tls_guard; return; }
    Record rec;
    rec.ts_ns = now_ns();
    rec.fn    = (uintptr_t)this_fn;
    rec.type  = 1; // exit
    tlog.append(rec);
    --tls_guard;
}