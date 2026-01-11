
# Linux eBPF Firewall Project

Đây là một hệ thống Firewall hiệu năng cao sử dụng công nghệ **eBPF (Extended Berkeley Packet Filter)** trên Linux. Dự án kết hợp sức mạnh xử lý gói tin trong nhân (Kernel Space) với tính linh hoạt của User Space, cung cấp khả năng lọc gói tin, chặn DNS và quản trị trực quan.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![eBPF](https://img.shields.io/badge/tech-eBPF%20%7C%20XDP%20%7C%20TC-orange)

## Kiến trúc hệ thống

Dự án bao gồm 4 thành phần chính:

1.  **eBPF Core (`src/kernel`)**:
    *   Chạy trong Kernel Linux (Hook vào XDP và Traffic Control).
    *   Xử lý/Drops gói tin với tốc độ cực cao.
    *   Lọc theo 5-tuple (IP nguồn/đích, Port nguồn/đích, Giao thức).
    *   Phân tích và chặn DNS query độc hại.

2.  **Firewall Daemon (`src/user`)**:
    *   Chương trình C++ chạy ngầm (Daemon).
    *   Nạp chương trình eBPF vào kernel.
    *   Quản lý BPF Maps (thêm/xóa luật).
    *   Giao tiếp với các công cụ quản trị qua Unix Domain Socket (`/var/run/firewall.sock`).

3.  **CLI Tool (`firewall_control`)**:
    *   Công cụ dòng lệnh `firewallctl` để thêm/xóa luật nhanh chóng.

4.  **Web Dashboard (`src/firewall_web`)**:
    *   Giao diện web trực quan (Flask + Vue.js + TailwindCSS).
    *   Giám sát trạng thái và quản lý luật dễ dàng.

---

## Cài đặt & Build

### 1. Yêu cầu hệ thống (Prerequisites)
*   **OS**: Linux (Ubuntu 20.04/22.04+ khuyến nghị).
*   **Kernel**: Phiên bản 5.8 trở lên (hỗ trợ BTF).
*   **Tools**: `clang`, `llvm`, `make`, `cmake`, `bpftool`, `python3`.

```bash
# Cài đặt các gói cần thiết
sudo apt update
sudo apt install -y build-essential cmake clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)
sudo apt install -y python3 python3-pip python3-flask
```

### 2. Tải mã nguồn

```bash
git clone https://github.com/nnkhanhduy/projectOS.git
cd projectOS
git submodule update --init --recursive
```

### 3. Build Firewall Daemon (Core)

```bash
cd source/firewall
mkdir -p build && cd build
cmake ..
make
```

### 4. Build CLI Tool

```bash
# Mở terminal mới hoặc quay lại thư mục gốc
cd ../../source/firewall_control
mkdir -p build && cd build
cmake ..
make
```

---

## Hướng dẫn sử dụng

### 1. Chạy Firewall Daemon (Bắt buộc)
Daemon phải luôn chạy để firewall hoạt động.

```bash
# Tại source/firewall/build
sudo ./firewall_linux
```
*Lưu ý: Luôn chạy với quyền sudo.*

### 2. Sử dụng Web Dashboard (Khuyên dùng)
Giao diện đồ họa giúp bạn quản lý dễ dàng hơn.

```bash
# Mở terminal mới
cd source/firewall_web
sudo python3 app.py
```
👉 Truy cập trình duyệt tại: **http://localhost:5000**

### 3. Sử dụng CLI (`firewallctl`)

Nếu bạn thích dòng lệnh, dùng tool `firewallctl` đã build ở bước 4.

**Thêm luật chặn:**
```bash
# Chặn Ping (ICMP)
sudo ./firewallctl add --src_ip any --dst_ip any --src_port any --dst_port any --protocol ICMP --action DENY

# Chặn truy cập Web (Port 80)
sudo ./firewallctl add --src_ip any --dst_ip any --src_port any --dst_port 80 --protocol TCP --action DENY

# Chặn 1 IP cụ thể
sudo ./firewallctl add --src_ip 192.168.1.5 --dst_ip any --src_port any --dst_port any --protocol any --action DENY
```

**Chặn Domain (DNS):**
```bash
sudo ./firewallctl block_domain --domain tiktok.com
```

**Xóa luật:**
```bash
sudo ./firewallctl remove_rule --src_ip any --dst_ip any --src_port any --dst_port any --protocol ICMP
```

---

## Debugging & Logs

Để xem trực tiếp các sự kiện firewall đang xử lý (packets, blocks):

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
Bạn sẽ thấy log chi tiết từ Kernel eBPF như:
```
Checking DNS Query: example.com
Verdict found: 1
BLOCKING DNS Query for: example.com
```

---

## Phát triển mở rộng

*   **Logic Kernel**: `source/firewall/src/kernel/firewall.bpf.c`
*   **Daemon C++**: `source/firewall/src/user/`
*   **Web Backend**: `source/firewall_web/app.py`
