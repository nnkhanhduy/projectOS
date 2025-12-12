# MODULE FIREWALL


##  MỤC TIÊU

Client chịu trách nhiệm:

- Load mã user space chạy trong kernel để giám sát can thiệp gói tin
- Giao tiếp với ring buffer kernel eBPF 
- Nhận lệnh điều khiển từ chương trình firewall_control thực hiện cập nhập chính sách động 
---

##  CÔNG NGHỆ SỬ DỤNG

| Thành phần | Công nghệ |
|------------|-----------|
| Ngôn ngữ | LLVM/ Clang/ C++ |
| Tools | Cmake, bpftool |
| Thư viện chính | libbpf/ OpenSSL, Boost, cJson |
| Giao thức Chính | Unix Socket |

---

##  HƯỚNG DẪN CHẠY

### Cài đặt
```bash
sudo apt update
sudo apt install -y llvm clang build-essential
sudo apt install -y cmake
sudo apt install clang llvm
sudo apt install libbpf-dev
sudo apt install linux-tools-common linux-tools-$(uname -r)
sudo apt install -y libssl-dev
sudo apt install -y libboost-all-dev


### Chạy chương trình
```bash
cd source/firewall 
mkdir build && cd build
cmake .. && make 
sudo ./firewall
```

### Cấu hình hỗ trợ eBPF cho một số bản kernel chưa cấu hình
- Kiểm tra kernel có hỗ trợ bpf không 
```bash
    grep CONFIG_BPF /boot/config-$(uname -r)
```
---

##  CẤU TRÚC
```
├── tools
│   ├── cmake
│   │   ├── FindLibBpf.cmake
│   │   └── FindBpfObject.cmake
│   └── gen_vmlinux_h.sh
├── build
├── src
│   ├── user
│   │   ├── main.cpp
│   │   ├── utils.cpp
│   │   ├── connection.h
│   │   ├── common_user.h
│   │   ├── connection.cpp
│   │   └── utils.h
│   └── kernel
│       ├── firewall.bpf.c
│       └── common_kern.h
├── CMakeLists.txt
├── README.md
├── configs
│   ├── firewall_configs.json
│   └── ioc_dns.json
└── third_party
    ├── cjson
    ├── bpftool
    ├── libbpf
 

```

---

##  SỬ DỤNG
```bash
# Ví dụ gửi request
sudo ./firewall
```

---

##  GHI CHÚ

- Đảm bảo kernel version có hỗ trợ bpf (kernel verion >= 4.4)