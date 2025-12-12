# MODULE FIREWALL_CONTROL



##  MỤC TIÊU

firewall_control chịu trách nhiệm:
- Xử lí đầu vào người dùng, tạo dữ liệu json
- Gửi configs json động vừa tạo thông qua IPC đến deamon firewall 
- Nhận thông báo từ firewall

---

##  CÔNG NGHỆ SỬ DỤNG

| Thành phần | Công nghệ |
|------------|-----------|
| Ngôn ngữ | C++ |
| Tools | Cmake |
| Thư viện chính | OpenSSL, Boost, cJson |
| Giao thức Chính | Unix Socket |

---

## HƯỚNG DẪN CHẠY

### Cài đặt
```bash
```bash
sudo apt update
sudo apt install -y build-essential
sudo apt install -y cmake
sudo apt install clang llvm
sudo apt install -y libssl-dev
sudo apt install -y libboost-all-dev


### Khởi động firewall_control
```bash
cd source/firewall_control
mkdir build && cd build
cmake .. && make 
sudo ./firewallctl add --src_ip 203.162.88.119 --dst_ip any --src_port any --dst_port any --protocol any --action DENY # chặn kết nối đến 1 ip
sudo ./firewallctl add --src_ip any --dst_ip 80 --src_port any --dst_port any --protocol any --action DENY # chặn tấn công DDOS 
sudo ./firewallctl add --src_ip 203.162.88.119 --dst_ip any --src_port 443 --dst_port any --protocol any --action DENY # chặn kết nối 192.168.5.1 sử dụng giao thức UDP 
```
##  API

| Endpoint | Protocol | Method | Input | Output |
|----------|----------|--------|-------|--------|
| Unix Socket | Unix Domain Socket | Thêm/Xóa/Cập nhật rule| cấu hình JSON | true/ false |

---



## CẤU TRÚC
├── build

├── firewallctl.cpp

├── CMakeLists.txt

└── README.md


```

---

##  TEST
```bash
./firewall_control
```

---

##  GHI CHÚ

- Đảm bảo firewall đã chạy 