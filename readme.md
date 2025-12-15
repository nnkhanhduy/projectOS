### Hướng dẫn chạy:
Cài thirdparty
``` bash

git submodule update --init --recursive

Hoặc là 

git init
git submodule add https://github.com/DaveGamble/cJSON.git source/firewall/third_party/cjson
git submodule add https://github.com/libbpf/libbpf.git source/firewall/third_party/libbpf
git submodule add https://github.com/libbpf/bpftool.git source/firewall/third_party/bpftool

```
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
sudo apt install -y build-essential
sudo apt install -y cmake
sudo apt install clang llvm
sudo apt install -y libssl-dev
sudo apt install -y libboost-all-dev

### Cấu hình hỗ trợ eBPF cho một số bản kernel chưa cấu hình
- Kiểm tra kernel có hỗ trợ bpf không 
```bash
    grep CONFIG_BPF /boot/config-$(uname -r)
```

### Chạy chương trình (FireWall)
```bash
cd source/firewall 
mkdir build && cd build
cmake .. && make 
sudo ./firewall_linux
```


### Khởi động firewall_control
Giữ terminal cũ chạy firewall, Tạo terminal mới chạy song song các lệnh dưới đây:
```bash
cd source/firewall_control
mkdir build && cd build
cmake .. && make 
sudo ./firewallctl add --src_ip 203.162.88.119 --dst_ip any --src_port any --dst_port any --protocol any --action DENY # chặn kết nối đến 1 ip
sudo ./firewallctl add --src_ip any --dst_ip 80 --src_port any --dst_port any --protocol any --action DENY # chặn tấn công DDOS 
sudo ./firewallctl add --src_ip 203.162.88.119 --dst_ip any --src_port 443 --dst_port any --protocol any --action DENY # chặn kết nối 192.168.5.1 sử dụng giao thức UDP 
```