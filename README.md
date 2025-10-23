# DBScanner

Ứng dụng web (Flask) giúp rà soát nhanh cấu hình bảo mật của máy chủ cơ sở dữ liệu. Mặc dù hiện tích hợp các kiểm tra dành cho MySQL/MariaDB, kiến trúc được thiết kế để dễ dàng mở rộng sang hệ quản trị khác.

## Tính năng chính

- Giao diện tối giản: trang kết nối gọn nhẹ, báo cáo dạng bảng điều khiển với số liệu tổng quan và danh sách phát hiện dạng accordion.
- Bộ kiểm tra mặc định (MySQL/MariaDB):
  - Chính sách mật khẩu (`validate_password`, chiều dài, chữ hoa/thường, chữ số, ký tự đặc biệt).
  - Thiết lập kênh truyền (`require_secure_transport`, `local_infile`, `skip_grant_tables`).
  - Đặc quyền toàn cục nguy hiểm, tài khoản không mật khẩu, tài khoản ẩn danh, root đăng nhập từ xa.
  - Biến cấu hình nhạy cảm (`secure_file_priv`, `default_password_lifetime`, `sql_mode`, ...).
  - Ghi nhận kiểm tra bị bỏ qua (ví dụ thiếu quyền đọc `mysql.user`).
- Kết quả sắp xếp theo mức độ rủi ro (Critical, High, Medium, Low, Info) kèm khuyến nghị xử lý.
- Có thể chạy trực tiếp trên máy chủ hoặc từ máy quét trung gian.

> Ứng dụng chỉ đọc cấu hình và quyền; không chỉnh sửa dữ liệu cũng như không khai thác lỗ hổng.

## Cài đặt

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
```

## Chạy ứng dụng

```bash
flask --app app run --host 0.0.0.0 --port 5000 --debug
# Hoặc
python app.py --host 0.0.0.0 --port 5000 --debug
```

- Mở `http://127.0.0.1:5000/` nếu quét ngay trên máy chạy ứng dụng.
- Nếu truy cập từ thiết bị khác, dùng địa chỉ IP thực, ví dụ `http://192.168.1.180:5000/`.

Các biến môi trường `DBSCANNER_HOST`, `DBSCANNER_PORT`, `DBSCANNER_DEBUG=1` có thể dùng để cấu hình nhanh trong môi trường triển khai.

## Sử dụng

1. Cung cấp thông tin kết nối (host, port, tài khoản có quyền đọc cấu hình).
2. Nhấn **Bắt đầu quét**. Kết quả trả về gồm:
   - Thanh tóm tắt tổng phát hiện theo mức độ.
   - Danh sách phát hiện dạng accordion; nhấp để xem mô tả, dữ liệu chi tiết và khuyến nghị.
   - Thông tin kết nối và các biến cấu hình quan trọng.
   - Danh sách kiểm tra bị bỏ qua (nếu có) để tiện cấp quyền và quét lại.
3. Xuất/ghi lại báo cáo bằng cách in trang ra PDF nếu cần lưu trữ.

## Mở rộng kiểm tra

- Thêm hàm kiểm tra mới trong `scanner.py` và đưa vào danh sách `checks` tại `scan_mysql`. Bạn có thể bổ sung các bước quét chi tiết cho từng schema nếu cần.
- Tách logic kiểm tra theo từng backend (MySQL, PostgreSQL, MSSQL, v.v.) rồi điều chỉnh giao diện để người dùng chọn loại hệ CSDL trước khi quét.
- Tích hợp nhập cấu hình từ file, chạy lịch (cron) hoặc gửi cảnh báo qua webhook.

## Giới hạn

- Cần tài khoản có quyền đọc `information_schema` và các bảng hệ thống tương ứng. Thiếu quyền sẽ khiến một số mục bị bỏ qua.
- Không đánh giá được độ mạnh thực tế của mật khẩu (chỉ dựa trên chính sách).
- Không thay thế hoàn toàn cho kiểm thử thâm nhập hoặc audit chuyên sâu; nên kết hợp với các quy trình bảo mật khác.
