# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/duy/OS-firewall/source/firewall/third_party/libbpf/src"
  "/home/duy/OS-firewall/source/firewall/build/libbpf/src/libbpf-build"
  "/home/duy/OS-firewall/source/firewall/build/libbpf"
  "/home/duy/OS-firewall/source/firewall/build/libbpf/tmp"
  "/home/duy/OS-firewall/source/firewall/build/libbpf/src/libbpf-stamp"
  "/home/duy/OS-firewall/source/firewall/build/libbpf/src"
  "/home/duy/OS-firewall/source/firewall/build/libbpf/src/libbpf-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/duy/OS-firewall/source/firewall/build/libbpf/src/libbpf-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/duy/OS-firewall/source/firewall/build/libbpf/src/libbpf-stamp${cfgdir}") # cfgdir has leading slash
endif()
