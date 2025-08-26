# 1) Compile the profiler TU WITHOUT instrumentation:
g++ -O2 -std=c++20 -fno-instrument-functions -c prof_instrumentation.cpp

# 2) Compile the rest of your project WITH instrumentation:
#    Tip: exclude the profiler file (belt & suspenders) and any 3rd-party headers
#    you don't care about via the exclude lists.
g++ -O2 -std=c++20 -finstrument-functions \
    -finstrument-functions-exclude-file-list=prof_instrumentation.cpp,/usr/include \
    -c foo.cpp
g++ -O2 -std=c++20 -finstrument-functions \
    -finstrument-functions-exclude-file-list=prof_instrumentation.cpp,/usr/include \
    -c bar.cpp
# ... repeat for your sources ...

# 3) Link everything together. Use -rdynamic so dladdr can see main exe symbols.
g++ -O2 -rdynamic -pthread -o app *.o -ldl

# 4) Run. Optionally choose output file:
FPROF_OUT=/tmp/profile.csv ./app

# The report is printed at process exit to FPROF_OUT (CSV), or stderr if unset.
