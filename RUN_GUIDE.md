# Hướng dẫn chạy Firewall

Tài liệu này hướng dẫn chi tiết cách build, chạy và kiểm tra các tính năng của Firewall.

## 1. Yêu cầu hệ thống
- Linux (Ubuntu 20.04/22.04 khuyến nghị)
- Quyền sudo / root

## 2. Build dự án

Mở terminal tại thư mục gốc của project:

```bash
cd source/firewall
mkdir -p build
cd build
cmake ..
make
```

## 3. Chạy Firewall (Daemon)

Luôn chạy firewall với quyền `sudo`. Nó sẽ load các luật từ file `configs/firewall_configs.json` và `configs/ioc_dns.json` (trong thư mục `build` sau khi cmake copy sang).

```bash
# Tại thư mục source/firewall/build
sudo ./firewall_linux
```

> **Lưu ý quan trọng khi sửa Config:**
> Chương trình chạy file config trong thư mục `build`. Nếu bạn sửa file gốc ở `source/firewall/configs/`, bạn cần copy nó sang folder `build` hoặc chạy lại `make` để cập nhật.
> ```bash
> cp ../configs/ioc_dns.json .
> # Sau đó chạy lại sudo ./firewall_linux
> ```

## 4. Kiểm tra tính năng

### Block Domain (DNS)
1. Thêm domain vào `configs/ioc_dns.json` (ví dụ: "abc.com").
2. Copy sang build và chạy lại firewall.
3. Test bằng `nslookup`:
   ```bash
   # Query qua Google DNS (8.8.8.8) hoặc Cloudflare (1.1.1.1) để đi qua interface mạng thật
   nslookup abc.com 1.1.1.1
   ```
   **Kết quả:** Lệnh sẽ bị treo hoặc báo Timeout -> **Thành công**.

### Block IP / Port (Firewall Rules)
Sử dụng công cụ điều khiển `firewallctl` ở terminal khác.

1. Build công cụ điều khiển:
   ```bash
   cd source/firewall_control
   mkdir -p build && cd build
   cmake .. && make
   ```

2. Thêm luật chặn (Ví dụ chặn ping đến 1.1.1.1):
   ```bash
   sudo ./firewallctl add --src_ip any --dst_ip 1.1.1.1 --src_port any --dst_port any --protocol ICMP --action DENY
   ```

3. Thử ping:
   ```bash
   ping 1.1.1.1
   ```
   **Kết quả:** Timeout hoặc Packet filtered.

### Block Domain "Nóng" (Không cần restart)
   ```bash
   sudo ./firewallctl block_domain --domain tiktok.com
   ```
   Sau đó thử `nslookup tiktok.com 1.1.1.1` sẽ bị chặn ngay lập tức.

## 5. Xem Log
Để xem firewall đang làm gì (debug):
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
Bạn sẽ thấy các dòng log như `Checking DNS Query`, `BLOCKING DNS Query`, v.v.
