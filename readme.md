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

### Các lệnh ngoài 
```bash
Kiểm tra chương trình đã nạp chưa:
sudo bpftool prog show

Kiểm tra Maps (Xem luật & danh sách đen):
sudo bpftool map show

Dùng xdp monitor để trực quan hoá
sudo apt install xdp-tools
sudo xdp-monitor

# Xem danh sách các luật đang chạy
sudo ./firewallctl list

# Xóa một luật (Lưu ý: Nhập chính xác các tham số như lúc thêm)
sudo ./firewallctl del --src_ip any --dst_ip any --src_port any --dst_port 80 --protocol TCP --action DENY


```

### Bonus
# RULES
```bash
# [Chặn IP] Chặn toàn bộ kết nối từ IP 203.162.88.119 (Blacklist)
sudo ./firewallctl add --src_ip 203.162.88.119 --dst_ip any --src_port any --dst_port any --protocol any --action DENY
# Nếu đổi IP máy khác thành IP này, thử ping máy chủ. Kết quả sẽ là Timeout.

# [Chống DDoS Web] Chặn mọi truy cập vào cổng 80 (HTTP)
sudo ./firewallctl add --src_ip any --dst_ip any --src_port any --dst_port 80 --protocol TCP --action DENY
#  Gõ lệnh `curl -I http://google.com`.


# [Ẩn mình] Chặn Ping (ICMP) để không ai quét thấy máy chủ
sudo ./firewallctl add --src_ip any --dst_ip any --src_port any --dst_port any --protocol ICMP --action DENY
#  Gõ lệnh `ping 8.8.8.8`. -> "Request timeout" hoặc "Packet filtered".

# [Chặn Flood UDP] Chặn mọi gói tin UDP (thường dùng chống spam game/stream)
sudo ./firewallctl add --src_ip any --dst_ip any --src_port any --dst_port any --protocol UDP --action DENY
#  Dùng netcat gửi gói tin UDP: `echo "test" | nc -u 1.1.1.1 53` ->Gói tin không đi được, daemon hiện log [BLOCKED].
```

# 2. ADVANCED RULES
```bash

# [Chặn SSH Brute-force] Chỉ chặn IP 192.168.1.50 nếu cố truy cập SSH (Port 22)
sudo ./firewallctl add --src_ip 192.168.1.50 --dst_ip any --src_port any --dst_port 22 --protocol TCP --action DENY
# ➜ Kiểm tra: Từ máy có IP 192.168.1.50, chạy `ssh user@<ip-server>`. Kết nối sẽ thất bại.

# [Chặn DNS Amplification] Chặn các gói tin UDP xuất phát từ cổng 53
sudo ./firewallctl add --src_ip any --dst_ip any --src_port 53 --dst_port any --protocol UDP --action DENY
# ➜ Kiểm tra: Các phản hồi DNS từ server (port 53) sẽ bị chặn lại.

# [Egress Filter] Cấm máy chủ gửi kết nối đến IP độc hại 1.1.1.1
sudo ./firewallctl add --src_ip any --dst_ip 1.1.1.1 --src_port any --dst_port any --protocol any --action DENY
# ➜ Kiểm tra: Gõ `ping 1.1.1.1`. Kết quả sẽ là timeout.
```


