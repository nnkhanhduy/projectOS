# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/duy/OS-firewall/source/firewall/third_party/bpftool/src"
  "/home/duy/OS-firewall/source/firewall/build/bpftool/src/bpftool-build"
  "/home/duy/OS-firewall/source/firewall/build/bpftool"
  "/home/duy/OS-firewall/source/firewall/build/bpftool/tmp"
  "/home/duy/OS-firewall/source/firewall/build/bpftool/src/bpftool-stamp"
  "/home/duy/OS-firewall/source/firewall/build/bpftool/src"
  "/home/duy/OS-firewall/source/firewall/build/bpftool/src/bpftool-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/duy/OS-firewall/source/firewall/build/bpftool/src/bpftool-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/duy/OS-firewall/source/firewall/build/bpftool/src/bpftool-stamp${cfgdir}") # cfgdir has leading slash
endif()
