cmake_minimum_required(VERSION 3.25)

set(RPI_COMPILER_SECURITY_FLAGS 
    "-Wformat -Wformat=2 -Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -fstack-clash-protection -mbranch-protection=standard")

set(RPI_EXE_LINKER_FLAGS
    "-Wl,-z,relro,-z,now -Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,--as-needed -Wl,--no-copy-dt-needed-entries")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${RPI_COMPILER_SECURITY_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${RPI_EXE_LINKER_FLAGS}")