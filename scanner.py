from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set
import re

import pymysql
from pymysql.connections import Connection
from pymysql.cursors import DictCursor

SEVERITY_ORDER: Dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}

BOOLEAN_TRUE = {"ON", "1", "TRUE", "YES"}


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    recommendation: str
    details: Dict[str, Any]


class MySQLScanError(Exception):
    """Raised when the scanner cannot complete."""


def connect_mysql(cfg: Dict[str, Any]) -> Connection:
    try:
        connect_args: Dict[str, Any] = {
            "host": cfg["host"],
            "port": cfg["port"],
            "user": cfg["user"],
            "password": cfg["password"],
            "database": cfg.get("database"),
            "cursorclass": DictCursor,
        }
        if cfg.get("use_ssl"):
            # Cấu hình SSL với verify mode linh hoạt
            import ssl
            ssl_config = {
                "ssl": {
                    "ssl_version": ssl.PROTOCOL_TLS,
                    # Không verify certificate nếu dùng self-signed cert
                    "check_hostname": False,
                    "verify_mode": ssl.CERT_NONE,
                }
            }
            
            # Nếu có cung cấp SSL cert files
            if cfg.get("ssl_ca"):
                ssl_config["ssl"]["ca"] = cfg["ssl_ca"]
                ssl_config["ssl"]["verify_mode"] = ssl.CERT_REQUIRED
            if cfg.get("ssl_cert"):
                ssl_config["ssl"]["cert"] = cfg["ssl_cert"]
            if cfg.get("ssl_key"):
                ssl_config["ssl"]["key"] = cfg["ssl_key"]
            
            connect_args.update(ssl_config)
        return pymysql.connect(**connect_args)
    except pymysql.MySQLError as exc:
        raise MySQLScanError(f"Không thể kết nối MySQL: {exc}") from exc


def scan_mysql(cfg: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any]]:
    connection = connect_mysql(cfg)
    metadata: Dict[str, Any] = {
        "version": None,
        "current_user": None,
        "variables": {},
        "skipped_checks": [],
        "mysql_user_entries": None,
        "summary": {},
        "schema_analysis": None,
    }

    findings: List[Finding] = []

    with connection:
        with connection.cursor() as cursor:
            metadata["version"] = _fetch_scalar(cursor, "SELECT VERSION()")
            metadata["current_user"] = _fetch_scalar(cursor, "SELECT CURRENT_USER()")

            checks = [
                _check_validate_password,
                _check_secure_transport,
                _check_secure_file_priv,
                _check_default_password_lifetime,
                _check_local_infile,
                _check_skip_grant_tables,
                _check_global_privileges,
                _check_mysql_user_table,
                _check_anonymous_accounts,
                _check_remote_root_access,
                _check_password_expiration,
                _check_sql_mode_hardening,
                _check_binlog_exposure,
                _check_general_log_security,
                _check_symbolic_links,
                _check_automatic_sp_privileges,
                _check_test_database,
                _check_mysql_version,
                _check_ssl_configuration,
                _check_max_connections,
                _check_password_reuse_policy,
                _check_connection_control,
                _check_audit_log,
                _check_event_scheduler,
                _check_replication_security,
                _check_super_read_only,
                _check_log_error_verbosity,
                _check_show_databases_privilege,
                _check_definer_security,
                _check_default_authentication_plugin,
                _check_binlog_format,
            ]

            for check in checks:
                findings.extend(check(cursor, metadata))

    findings.sort(key=lambda finding: SEVERITY_ORDER.get(finding.severity, len(SEVERITY_ORDER)))
    metadata["summary"] = _summarize_findings(findings)
    return findings, metadata


def _summarize_findings(findings: List[Finding]) -> Dict[str, Any]:
    summary = {"total": len(findings), "by_severity": {level: 0 for level in SEVERITY_ORDER}}
    for finding in findings:
        level = finding.severity if finding.severity in summary["by_severity"] else "Info"
        summary["by_severity"].setdefault(level, 0)
        summary["by_severity"][level] += 1
    return summary


def _fetch_scalar(
    cursor: DictCursor,
    query: str,
    params: Optional[Iterable[Any]] = None,
) -> Optional[Any]:
    cursor.execute(query, params)
    row = cursor.fetchone()
    if not row:
        return None
    return next(iter(row.values()))


def _execute(
    cursor: DictCursor,
    query: str,
    params: Optional[Iterable[Any]] = None,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    try:
        cursor.execute(query, params)
        return list(cursor.fetchall()), None
    except pymysql.MySQLError as exc:
        return None, str(exc)


def _register_skip(metadata: Dict[str, Any], check_id: str, reason: str) -> None:
    metadata["skipped_checks"].append({"check": check_id, "reason": reason})


def _register_variable(metadata: Dict[str, Any], key: str, value: Any) -> None:
    metadata["variables"][key] = value


def _check_validate_password(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'validate_password.%'")
    if error:
        _register_skip(metadata, "validate_password", error)
        return []

    variables = {row["Variable_name"]: row["Value"] for row in rows}
    metadata["variables"]["validate_password"] = variables

    policy = variables.get("validate_password.policy")
    length = variables.get("validate_password.length")
    mixed_case = variables.get("validate_password.mixed_case_count")
    number_count = variables.get("validate_password.number_count")
    special_char = variables.get("validate_password.special_char_count")

    findings: List[Finding] = []

    if not policy:
        findings.append(
            Finding(
                title="Chính sách mật khẩu không được bật",
                severity="Medium",
                description="Plugin validate_password dường như bị vô hiệu hóa, MySQL không kiểm tra độ mạnh mật khẩu.",
                recommendation="Bật plugin validate_password và đặt policy ở mức MEDIUM hoặc STRONG.",
                details=variables,
            )
        )
        return findings

    if policy.upper() in {"LOW", "0"}:
        findings.append(
            Finding(
                title="Chính sách mật khẩu quá thấp",
                severity="Medium",
                description=f"validate_password.policy đang là {policy}, chỉ cung cấp yêu cầu tối thiểu.",
                recommendation="Nâng validate_password.policy lên MEDIUM hoặc STRONG để tăng độ mạnh mật khẩu.",
                details={"policy": policy, "length": length},
            )
        )

    if length and length.isdigit() and int(length) < 12:
        findings.append(
            Finding(
                title="Độ dài mật khẩu tối thiểu thấp",
                severity="Low",
                description=f"validate_password.length đặt ở {length}, thấp hơn khuyến nghị 12 ký tự.",
                recommendation="Tăng validate_password.length lên ít nhất 12 ký tự.",
                details={"length": length},
            )
        )

    if mixed_case and mixed_case.isdigit() and int(mixed_case) < 1:
        findings.append(
            Finding(
                title="Không yêu cầu chữ hoa/thường trong mật khẩu",
                severity="Low",
                description="validate_password.mixed_case_count đặt 0 nên mật khẩu có thể chỉ cần một loại chữ.",
                recommendation="Thiết lập mixed_case_count >= 1 để yêu cầu cả chữ hoa và chữ thường.",
                details={"mixed_case_count": mixed_case},
            )
        )

    if number_count and number_count.isdigit() and int(number_count) < 1:
        findings.append(
            Finding(
                title="Không yêu cầu số trong mật khẩu",
                severity="Low",
                description="validate_password.number_count đặt 0 nên mật khẩu có thể không chứa số.",
                recommendation="Đặt number_count >= 1 để bắt buộc có số.",
                details={"number_count": number_count},
            )
        )

    if special_char and special_char.isdigit() and int(special_char) < 1:
        findings.append(
            Finding(
                title="Không yêu cầu ký tự đặc biệt trong mật khẩu",
                severity="Low",
                description="validate_password.special_char_count đặt 0 nên cho phép mật khẩu thiếu ký tự đặc biệt.",
                recommendation="Đặt special_char_count >= 1 để tăng độ phức tạp.",
                details={"special_char_count": special_char},
            )
        )

    return findings


def _check_secure_transport(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'require_secure_transport'")
    if error:
        _register_skip(metadata, "secure_transport", error)
        return []

    value = rows[0]["Value"] if rows else None
    _register_variable(metadata, "require_secure_transport", value)

    if value is None or value.upper() != "ON":
        return [
            Finding(
                title="Máy chủ chấp nhận kết nối không mã hóa",
                severity="High",
                description="require_secure_transport đang tắt nên client có thể kết nối qua TCP không mã hóa.",
                recommendation="Bật require_secure_transport=ON để buộc kết nối TLS/SSL.",
                details={"require_secure_transport": value},
            )
        ]
    return []


def _check_secure_file_priv(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'secure_file_priv'")
    if error:
        _register_skip(metadata, "secure_file_priv", error)
        return []

    value = rows[0]["Value"] if rows else None
    _register_variable(metadata, "secure_file_priv", value)

    if value in (None, "", "NULL"):
        return [
            Finding(
                title="secure_file_priv chưa cấu hình",
                severity="High",
                description="secure_file_priv trống nên LOAD DATA/SELECT INTO OUTFILE có thể đọc/ghi toàn hệ thống tập tin.",
                recommendation="Đặt secure_file_priv tới thư mục biệt lập hoặc vô hiệu hóa nếu không sử dụng.",
                details={"secure_file_priv": value},
            )
        ]
    return []


def _check_default_password_lifetime(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'default_password_lifetime'")
    if error:
        _register_skip(metadata, "default_password_lifetime", error)
        return []

    value = rows[0]["Value"] if rows else None
    _register_variable(metadata, "default_password_lifetime", value)

    if value in (None, "0", "NULL"):
        return [
            Finding(
                title="Mật khẩu không có thời hạn",
                severity="Low",
                description="default_password_lifetime bằng 0 nên người dùng không cần đổi mật khẩu định kỳ.",
                recommendation="Thiết lập default_password_lifetime (ví dụ 90 ngày) để buộc đổi mật khẩu.",
                details={"default_password_lifetime": value},
            )
        ]
    return []


def _check_local_infile(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'local_infile'")
    if error:
        _register_skip(metadata, "local_infile", error)
        return []

    value = rows[0]["Value"] if rows else None
    _register_variable(metadata, "local_infile", value)

    if value and str(value).upper() in BOOLEAN_TRUE:
        return [
            Finding(
                title="Cho phép LOAD DATA LOCAL INFILE",
                severity="High",
                description="local_infile đang bật, kẻ tấn công có thể lợi dụng tính năng này để đọc file tùy ý từ máy client.",
                recommendation="Tắt biến local_infile trừ khi thực sự cần thiết.",
                details={"local_infile": value},
            )
        ]
    return []


def _check_skip_grant_tables(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'skip_grant_tables'")
    if error:
        _register_skip(metadata, "skip_grant_tables", error)
        return []

    value = rows[0]["Value"] if rows else None
    _register_variable(metadata, "skip_grant_tables", value)

    if value and str(value).upper() in BOOLEAN_TRUE:
        return [
            Finding(
                title="Máy chủ bỏ qua bảng phân quyền",
                severity="Critical",
                description="skip_grant_tables đang bật khiến MySQL bỏ qua toàn bộ xác thực tài khoản.",
                recommendation="Tắt skip_grant_tables ngay lập tức và khởi động lại MySQL.",
                details={"skip_grant_tables": value},
            )
        ]
    return []


def _check_global_privileges(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(
        cursor,
        """
        SELECT
            GRANTEE,
            PRIVILEGE_TYPE,
            IS_GRANTABLE
        FROM information_schema.user_privileges
        """
    )
    if error:
        _register_skip(metadata, "global_privileges", error)
        return []

    high_risk = {
        "SUPER",
        "FILE",
        "SHUTDOWN",
        "PROCESS",
        "CREATE USER",
        "GRANT OPTION",
        "RELOAD",
        "REPLICATION SLAVE",
        "REPLICATION CLIENT",
        "CREATE TABLESPACE",
    }

    privilege_map: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        grantee = row["GRANTEE"]
        entry = privilege_map.setdefault(
            grantee,
            {"privileges": set(), "grant_option": False},
        )
        entry["privileges"].add(row["PRIVILEGE_TYPE"])
        if row["IS_GRANTABLE"] == "YES":
            entry["grant_option"] = True

    excessive_accounts: List[Dict[str, Any]] = []
    for grantee, info in privilege_map.items():
        privileges = info["privileges"]
        grant_option = info["grant_option"] or "GRANT OPTION" in privileges
        if "ALL PRIVILEGES" in privileges or grant_option or privileges.intersection(high_risk):
            user, host = _split_grantee(grantee)
            excessive_accounts.append(
                {
                    "user": user,
                    "host": host,
                    "privileges": sorted(privileges),
                    "grant_option": grant_option,
                }
            )

    if not excessive_accounts:
        return []

    return [
        Finding(
            title="Tài khoản có quyền global quá rộng",
            severity="High",
            description="Có tài khoản sở hữu đặc quyền cao (SUPER, FILE, GRANT OPTION hoặc ALL PRIVILEGES).",
            recommendation="Giảm đặc quyền global và chuyển sang cấp quyền trên schema/table cụ thể.",
            details={"accounts": excessive_accounts},
        )
    ]


def _split_grantee(grantee: str) -> Tuple[str, str]:
    if "@" not in grantee:
        return grantee.strip("'"), "%"
    user_part, host_part = grantee.split("@", 1)
    return user_part.strip("'"), host_part.strip("'")


def _check_mysql_user_table(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(
        cursor,
        """
        SELECT
            user,
            host,
            plugin,
            account_locked,
            IFNULL(authentication_string, '') AS authentication_string
        FROM mysql.user
        """
    )
    if error:
        _register_skip(metadata, "mysql_user_table", error)
        return []

    metadata["mysql_user_entries"] = len(rows)

    empty_password_accounts: List[Dict[str, Any]] = []
    wildcard_accounts: List[Dict[str, Any]] = []
    insecure_plugins: List[Dict[str, Any]] = []

    for row in rows:
        auth_string = row["authentication_string"]
        plugin = row["plugin"] or ""
        host = row["host"]
        user = row["user"]

        if not auth_string:
            empty_password_accounts.append({"user": user, "host": host})

        if host == "%" and user not in {"mysql.session", "mysql.sys"}:
            wildcard_accounts.append({"user": user, "host": host})

        if plugin in {"mysql_old_password", "mysql_clear_password"}:
            insecure_plugins.append({"user": user, "host": host, "plugin": plugin})

    findings: List[Finding] = []

    if empty_password_accounts:
        findings.append(
            Finding(
                title="Tài khoản MySQL không đặt mật khẩu",
                severity="Critical",
                description="Có tài khoản MySQL có authentication_string trống.",
                recommendation="Đặt mật khẩu mạnh hoặc vô hiệu hóa các tài khoản này ngay lập tức.",
                details={"accounts": empty_password_accounts},
            )
        )

    if wildcard_accounts:
        findings.append(
            Finding(
                title="Tài khoản mở truy cập từ mọi địa chỉ IP",
                severity="Medium",
                description="Một số tài khoản có host='%' cho phép đăng nhập từ bất kỳ nơi đâu.",
                recommendation="Giới hạn host theo địa chỉ IP cụ thể hoặc subnet tin cậy.",
                details={"accounts": wildcard_accounts},
            )
        )

    if insecure_plugins:
        findings.append(
            Finding(
                title="Tài khoản dùng plugin xác thực không an toàn",
                severity="High",
                description="Phát hiện tài khoản sử dụng mysql_old_password hoặc mysql_clear_password.",
                recommendation="Chuyển sang plugin xác thực mới hơn như caching_sha2_password hoặc mysql_native_password.",
                details={"accounts": insecure_plugins},
            )
        )

    return findings


def _check_anonymous_accounts(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(
        cursor,
        """
        SELECT user, host
        FROM mysql.user
        WHERE user = ''
        """
    )
    if error:
        _register_skip(metadata, "anonymous_accounts", error)
        return []

    if not rows:
        return []

    return [
        Finding(
            title="Tài khoản ẩn danh tồn tại",
            severity="High",
            description="MySQL có tài khoản user rỗng, cho phép đăng nhập mà không cần tên người dùng.",
            recommendation="Xóa các tài khoản ẩn danh hoặc đặt tên/mật khẩu rõ ràng.",
            details={"accounts": rows},
        )
    ]


def _check_remote_root_access(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(
        cursor,
        """
        SELECT user, host
        FROM mysql.user
        WHERE user = 'root' AND host NOT IN ('localhost', '127.0.0.1', '::1')
        """
    )
    if error:
        _register_skip(metadata, "remote_root_access", error)
        return []

    if not rows:
        return []

    return [
        Finding(
            title="Tài khoản root có thể đăng nhập từ xa",
            severity="High",
            description="Tài khoản root được phép đăng nhập từ host khác localhost, tăng rủi ro bị brute-force.",
            recommendation="Giới hạn root chỉ đăng nhập local hoặc tạo tài khoản admin riêng với chính sách mạnh hơn.",
            details={"accounts": rows},
        )
    ]


def _check_password_expiration(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(
        cursor,
        """
        SELECT user, host
        FROM mysql.user
        WHERE password_expired = 'Y'
        """
    )
    if error:
        if "Unknown column" in error:
            _register_skip(metadata, "password_expiration", "Trường password_expired không khả dụng.")
            return []
        _register_skip(metadata, "password_expiration", error)
        return []

    if not rows:
        return []

    return [
        Finding(
            title="Có tài khoản yêu cầu đổi mật khẩu",
            severity="Info",
            description="Một số tài khoản có trạng thái password_expired=Y, người dùng cần đổi mật khẩu ở lần đăng nhập tiếp theo.",
            recommendation="Xác thực với chủ tài khoản và buộc họ đổi mật khẩu.",
            details={"accounts": rows},
        )
    ]


def _check_sql_mode_hardening(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'sql_mode'")
    if error:
        _register_skip(metadata, "sql_mode", error)
        return []

    value = rows[0]["Value"] if rows else ""
    _register_variable(metadata, "sql_mode", value)
    modes = {mode.strip().upper() for mode in value.split(",") if mode}

    missing: List[str] = []
    for required in {"STRICT_TRANS_TABLES", "ERROR_FOR_DIVISION_BY_ZERO", "NO_ENGINE_SUBSTITUTION"}:
        if required not in modes:
            missing.append(required)

    findings: List[Finding] = []
    if missing:
        findings.append(
            Finding(
                title="sql_mode thiếu các chế độ an toàn",
                severity="Medium",
                description="sql_mode chưa bật đủ các chế độ giúp phát hiện dữ liệu sai (ví dụ STRICT_TRANS_TABLES).",
                recommendation="Bổ sung các giá trị còn thiếu vào cấu hình sql_mode.",
                details={"sql_mode": value, "missing_modes": missing},
            )
        )

    return findings


# ==================== NEW SECURITY CHECKS ====================

def _check_binlog_exposure(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra cấu hình binary log có thể lộ thông tin nhạy cảm"""
    findings: List[Finding] = []
    
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'log_bin'")
    if error:
        _register_skip(metadata, "binlog_exposure", error)
        return []
    
    log_bin = rows[0]["Value"] if rows else "OFF"
    _register_variable(metadata, "log_bin", log_bin)
    
    if log_bin.upper() in BOOLEAN_TRUE:
        # Kiểm tra vị trí binlog
        rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'log_bin_basename'")
        log_path = rows[0]["Value"] if rows else None
        
        # Kiểm tra expire_logs_days
        rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'expire_logs_days'")
        expire_days = rows[0]["Value"] if rows else "0"
        
        if expire_days == "0":
            findings.append(
                Finding(
                    title="Binary log không tự động xóa",
                    severity="Medium",
                    description="expire_logs_days đặt 0 nên binlog có thể tồn tại vô thời hạn, chiếm dung lượng và chứa dữ liệu nhạy cảm.",
                    recommendation="Đặt expire_logs_days với giá trị phù hợp (ví dụ 7-30 ngày).",
                    details={"expire_logs_days": expire_days, "log_path": log_path},
                )
            )
    
    return findings


def _check_general_log_security(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra general log và slow query log có thể ghi mật khẩu"""
    findings: List[Finding] = []
    
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'general_log'")
    if error:
        _register_skip(metadata, "general_log", error)
        return findings
    
    general_log = rows[0]["Value"] if rows else "OFF"
    _register_variable(metadata, "general_log", general_log)
    
    if general_log.upper() in BOOLEAN_TRUE:
        rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'general_log_file'")
        log_file = rows[0]["Value"] if rows else None
        
        findings.append(
            Finding(
                title="General log đang bật",
                severity="Medium",
                description="General log ghi lại tất cả query bao gồm cả mật khẩu trong câu lệnh CREATE USER, GRANT.",
                recommendation="Tắt general_log trong môi trường production hoặc đảm bảo file log có quyền truy cập hạn chế.",
                details={"general_log": general_log, "log_file": log_file},
            )
        )
    
    # Kiểm tra slow query log
    rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'slow_query_log'")
    slow_log = rows[0]["Value"] if rows else "OFF"
    _register_variable(metadata, "slow_query_log", slow_log)
    
    if slow_log.upper() in BOOLEAN_TRUE:
        rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'log_queries_not_using_indexes'")
        log_no_index = rows[0]["Value"] if rows else "OFF"
        
        if log_no_index.upper() in BOOLEAN_TRUE:
            findings.append(
                Finding(
                    title="Slow log ghi tất cả query không dùng index",
                    severity="Low",
                    description="log_queries_not_using_indexes có thể gây đầy disk nhanh chóng.",
                    recommendation="Tắt log_queries_not_using_indexes sau khi tối ưu xong.",
                    details={"log_queries_not_using_indexes": log_no_index},
                )
            )
    
    return findings


def _check_symbolic_links(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra symbolic link có thể dẫn đến symlink attack"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'symbolic_links'")
    if error or not rows:
        return []
    
    value = rows[0]["Value"]
    _register_variable(metadata, "symbolic_links", value)
    
    # Trên Windows, symbolic_links luôn disabled
    if value and value.upper() in BOOLEAN_TRUE:
        return [
            Finding(
                title="Symbolic links được bật",
                severity="Medium",
                description="have_symlink=YES cho phép tạo symlink, có thể bị lợi dụng để truy cập file tùy ý.",
                recommendation="Tắt symbolic-links trong my.cnf nếu không cần thiết.",
                details={"symbolic_links": value},
            )
        ]
    return []


def _check_automatic_sp_privileges(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra automatic_sp_privileges có thể cấp quyền tự động"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'automatic_sp_privileges'")
    if error or not rows:
        return []
    
    value = rows[0]["Value"]
    _register_variable(metadata, "automatic_sp_privileges", value)
    
    if value and value.upper() in BOOLEAN_TRUE:
        return [
            Finding(
                title="Tự động cấp quyền cho stored procedure",
                severity="Low",
                description="automatic_sp_privileges=ON tự động cấp ALTER/EXECUTE cho người tạo procedure, có thể không mong muốn.",
                recommendation="Xem xét tắt và quản lý quyền stored procedure thủ công.",
                details={"automatic_sp_privileges": value},
            )
        ]
    return []


def _check_test_database(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra database test mặc định vẫn tồn tại"""
    rows, error = _execute(cursor, "SHOW DATABASES LIKE 'test'")
    if error:
        return []
    
    if rows:
        return [
            Finding(
                title="Database 'test' mặc định vẫn tồn tại",
                severity="Low",
                description="Database test thường có quyền truy cập rộng rãi và không được sử dụng trong production.",
                recommendation="Xóa database test: DROP DATABASE test;",
                details={"databases": [row["Database"] for row in rows]},
            )
        ]
    return []


def _check_mysql_version(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra phiên bản MySQL có lỗ hổng đã biết"""
    version_string = metadata.get("version", "")
    if not version_string:
        return []
    
    # Parse version number
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_string)
    if not match:
        return []
    
    major, minor, patch = map(int, match.groups())
    findings: List[Finding] = []
    
    # MySQL 5.x đã EOL
    if major == 5:
        findings.append(
            Finding(
                title="Phiên bản MySQL đã lỗi thời",
                severity="High",
                description=f"MySQL {version_string} thuộc dòng 5.x đã hết hỗ trợ, có nhiều lỗ hổng bảo mật đã biết.",
                recommendation="Nâng cấp lên MySQL 8.0 hoặc mới hơn.",
                details={"version": version_string},
            )
        )
    
    # MySQL < 8.0.28 có lỗ hổng nghiêm trọng
    elif major == 8 and minor == 0 and patch < 28:
        findings.append(
            Finding(
                title="Phiên bản MySQL có lỗ hổng bảo mật",
                severity="High",
                description=f"MySQL {version_string} có các lỗ hổng CVE đã được vá trong 8.0.28+",
                recommendation="Nâng cấp lên MySQL 8.0.28 hoặc mới hơn.",
                details={"version": version_string},
            )
        )
    
    return findings


def _check_ssl_configuration(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra cấu hình SSL/TLS yếu"""
    findings: List[Finding] = []
    
    # Kiểm tra have_ssl
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'have_ssl'")
    if error or not rows:
        return findings
    
    have_ssl = rows[0]["Value"]
    _register_variable(metadata, "have_ssl", have_ssl)
    
    if have_ssl.upper() not in {"YES", "ON"}:
        findings.append(
            Finding(
                title="SSL/TLS không được cấu hình",
                severity="High",
                description="have_ssl không phải YES, server không hỗ trợ kết nối mã hóa.",
                recommendation="Cấu hình SSL certificate và enable SSL trong my.cnf.",
                details={"have_ssl": have_ssl},
            )
        )
        return findings
    
    # Kiểm tra TLS version
    rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'tls_version'")
    if rows:
        tls_version = rows[0]["Value"]
        _register_variable(metadata, "tls_version", tls_version)
        
        if "TLSv1," in tls_version or "TLSv1.0" in tls_version or "TLSv1.1" in tls_version:
            findings.append(
                Finding(
                    title="Hỗ trợ TLS phiên bản cũ",
                    severity="Medium",
                    description="TLS 1.0 và 1.1 đã không còn an toàn, nên vô hiệu hóa.",
                    recommendation="Chỉ cho phép TLSv1.2 và TLSv1.3: SET GLOBAL tls_version='TLSv1.2,TLSv1.3';",
                    details={"tls_version": tls_version},
                )
            )
    
    # Kiểm tra ssl_cipher
    rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'ssl_cipher'")
    if rows:
        ssl_cipher = rows[0]["Value"]
        weak_ciphers = ["DES", "RC4", "MD5", "NULL", "EXPORT"]
        
        if any(weak in ssl_cipher.upper() for weak in weak_ciphers):
            findings.append(
                Finding(
                    title="SSL cipher yếu được cho phép",
                    severity="Medium",
                    description="Cấu hình ssl_cipher cho phép các thuật toán mã hóa yếu.",
                    recommendation="Chỉ định các cipher suite mạnh, loại bỏ DES, RC4, MD5.",
                    details={"ssl_cipher": ssl_cipher},
                )
            )
    
    return findings


def _check_max_connections(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra max_connections có thể dẫn đến DoS"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'max_connections'")
    if error or not rows:
        return []
    
    max_conn = rows[0]["Value"]
    _register_variable(metadata, "max_connections", max_conn)
    
    try:
        max_conn_int = int(max_conn)
        if max_conn_int > 1000:
            return [
                Finding(
                    title="max_connections đặt quá cao",
                    severity="Low",
                    description=f"max_connections={max_conn} có thể làm cạn kiệt tài nguyên server khi có attack.",
                    recommendation="Đặt max_connections phù hợp với tài nguyên server (thường 150-500).",
                    details={"max_connections": max_conn},
                )
            ]
        elif max_conn_int < 50:
            return [
                Finding(
                    title="max_connections đặt quá thấp",
                    severity="Info",
                    description=f"max_connections={max_conn} có thể gây từ chối kết nối khi traffic tăng.",
                    recommendation="Xem xét tăng max_connections nếu ứng dụng cần nhiều kết nối đồng thời.",
                    details={"max_connections": max_conn},
                )
            ]
    except ValueError:
        pass
    
    return []


def _check_password_reuse_policy(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra chính sách không cho phép dùng lại mật khẩu cũ"""
    findings: List[Finding] = []
    
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'password_history'")
    if error:
        return findings
    
    if rows:
        history = rows[0]["Value"]
        _register_variable(metadata, "password_history", history)
        
        if history == "0":
            findings.append(
                Finding(
                    title="Không có chính sách lịch sử mật khẩu",
                    severity="Low",
                    description="password_history=0 cho phép người dùng dùng lại mật khẩu cũ ngay lập tức.",
                    recommendation="Đặt password_history >=5 để ngăn tái sử dụng mật khẩu.",
                    details={"password_history": history},
                )
            )
    
    rows, _ = _execute(cursor, "SHOW VARIABLES LIKE 'password_reuse_interval'")
    if rows:
        interval = rows[0]["Value"]
        _register_variable(metadata, "password_reuse_interval", interval)
        
        if interval == "0":
            findings.append(
                Finding(
                    title="Không có khoảng thời gian tái sử dụng mật khẩu",
                    severity="Low",
                    description="password_reuse_interval=0 không giới hạn thời gian trước khi dùng lại mật khẩu.",
                    recommendation="Đặt password_reuse_interval >=365 ngày.",
                    details={"password_reuse_interval": interval},
                )
            )
    
    return findings


def _check_connection_control(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra plugin connection_control chống brute force"""
    rows, error = _execute(
        cursor,
        "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE 'connection_control%'"
    )
    if error:
        return []
    
    if not rows or not any(row["PLUGIN_STATUS"] == "ACTIVE" for row in rows):
        return [
            Finding(
                title="Plugin chống brute-force chưa được bật",
                severity="Medium",
                description="CONNECTION_CONTROL plugin giúp chặn brute-force bằng cách delay kết nối sau nhiều lần thất bại.",
                recommendation="Cài đặt và kích hoạt: INSTALL PLUGIN connection_control SONAME 'connection_control.so';",
                details={"plugins": rows if rows else []},
            )
        ]
    
    return []


def _check_audit_log(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra audit log plugin để theo dõi hoạt động"""
    rows, error = _execute(
        cursor,
        "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE '%audit%'"
    )
    if error:
        return []
    
    if not rows or not any(row["PLUGIN_STATUS"] == "ACTIVE" for row in rows):
        return [
            Finding(
                title="Audit logging chưa được cấu hình",
                severity="Info",
                description="Không có plugin audit log để theo dõi và ghi lại các hoạt động trên database.",
                recommendation="Cân nhắc cài đặt MySQL Enterprise Audit hoặc MariaDB Audit Plugin cho compliance.",
                details={},
            )
        ]
    
    return []


def _check_event_scheduler(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra event scheduler có thể bị lợi dụng"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'event_scheduler'")
    if error or not rows:
        return []
    
    value = rows[0]["Value"]
    _register_variable(metadata, "event_scheduler", value)
    
    if value.upper() in BOOLEAN_TRUE:
        # Kiểm tra xem có event nào được tạo bởi user không phải root
        rows, _ = _execute(
            cursor,
            """
            SELECT EVENT_NAME, DEFINER, EVENT_DEFINITION
            FROM information_schema.EVENTS
            LIMIT 10
            """
        )
        
        if rows:
            return [
                Finding(
                    title="Event Scheduler đang chạy",
                    severity="Low",
                    description="Event scheduler đang bật và có scheduled events, cần đảm bảo các events được tạo an toàn.",
                    recommendation="Rà soát các events, đảm bảo DEFINER có quyền tối thiểu.",
                    details={"event_scheduler": value, "events_count": len(rows)},
                )
            ]
    
    return []


def _check_replication_security(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra bảo mật replication"""
    findings: List[Finding] = []
    
    # Kiểm tra có phải slave không
    rows, error = _execute(cursor, "SHOW SLAVE STATUS")
    if error:
        return findings
    
    if rows and len(rows) > 0:
        slave_status = rows[0]
        
        # Kiểm tra SSL replication
        slave_ssl = slave_status.get("Master_SSL_Allowed", "No")
        if slave_ssl.upper() != "YES":
            findings.append(
                Finding(
                    title="Replication không sử dụng SSL",
                    severity="High",
                    description="Kết nối replication từ slave tới master không được mã hóa.",
                    recommendation="Cấu hình SSL cho replication: CHANGE MASTER TO MASTER_SSL=1;",
                    details={"Master_SSL_Allowed": slave_ssl},
                )
            )
    
    # Kiểm tra replication user - sử dụng SHOW GRANTS thay vì query mysql.user
    rows, error = _execute(
        cursor,
        """
        SELECT GRANTEE, PRIVILEGE_TYPE
        FROM information_schema.user_privileges
        WHERE PRIVILEGE_TYPE IN ('REPLICATION SLAVE', 'REPLICATION CLIENT')
        """
    )
    
    if error:
        return findings
    
    if rows:
        wildcard_users = []
        for row in rows:
            grantee = row["GRANTEE"]
            # Parse grantee format: 'user'@'host'
            user, host = _split_grantee(grantee)
            if host == "%":
                wildcard_users.append({"user": user, "host": host, "privilege": row["PRIVILEGE_TYPE"]})
        
        if wildcard_users:
            findings.append(
                Finding(
                    title="Replication user có host wildcards",
                    severity="Medium",
                    description=f"Có {len(wildcard_users)} user replication có thể kết nối từ mọi nơi.",
                    recommendation="Giới hạn host của replication user theo IP cụ thể.",
                    details={"replication_users": wildcard_users},
                )
            )
    
    return findings


def _check_super_read_only(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra super_read_only trên slave"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'super_read_only'")
    if error or not rows:
        return []
    
    value = rows[0]["Value"]
    _register_variable(metadata, "super_read_only", value)
    
    # Kiểm tra nếu là slave
    rows, _ = _execute(cursor, "SHOW SLAVE STATUS")
    if rows and len(rows) > 0:
        if value.upper() != "ON":
            return [
                Finding(
                    title="Slave không ở chế độ super_read_only",
                    severity="Medium",
                    description="Slave server nên bật super_read_only để ngăn ghi dữ liệu trực tiếp.",
                    recommendation="Bật super_read_only=ON trên tất cả slave servers.",
                    details={"super_read_only": value},
                )
            ]
    
    return []


def _check_log_error_verbosity(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra log_error_verbosity có thể lộ thông tin nhạy cảm"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'log_error_verbosity'")
    if error or not rows:
        return []
    
    value = rows[0]["Value"]
    _register_variable(metadata, "log_error_verbosity", value)
    
    try:
        verbosity = int(value)
        if verbosity >= 3:
            return [
                Finding(
                    title="Log error verbosity quá cao",
                    severity="Low",
                    description="log_error_verbosity=3 ghi quá nhiều thông tin debug, có thể lộ thông tin nhạy cảm.",
                    recommendation="Đặt log_error_verbosity=2 trong production.",
                    details={"log_error_verbosity": value},
                )
            ]
    except ValueError:
        pass
    
    return []


def _check_show_databases_privilege(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra quyền SHOW DATABASES có thể lộ cấu trúc hệ thống"""
    rows, error = _execute(
        cursor,
        """
        SELECT GRANTEE, PRIVILEGE_TYPE
        FROM information_schema.user_privileges
        WHERE PRIVILEGE_TYPE IN ('SHOW DATABASES', 'SELECT')
        """
    )
    if error:
        return []
    
    # Đếm số user có quyền SHOW DATABASES
    show_db_users = [row for row in rows if row["PRIVILEGE_TYPE"] == "SHOW DATABASES"]
    
    if len(show_db_users) > 5:
        return [
            Finding(
                title="Quá nhiều user có quyền SHOW DATABASES",
                severity="Low",
                description=f"Có {len(show_db_users)} tài khoản có quyền SHOW DATABASES, có thể lộ cấu trúc database.",
                recommendation="Giới hạn quyền SHOW DATABASES chỉ cho admin cần thiết.",
                details={"users_count": len(show_db_users)},
            )
        ]
    
    return []


def _check_definer_security(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra stored procedures/views có DEFINER không an toàn"""
    findings: List[Finding] = []
    
    # Kiểm tra procedures với DEFINER có quyền cao
    rows, error = _execute(
        cursor,
        """
        SELECT ROUTINE_NAME, DEFINER, SECURITY_TYPE, ROUTINE_SCHEMA
        FROM information_schema.ROUTINES
        WHERE DEFINER LIKE '%root%' OR DEFINER LIKE '%admin%'
        LIMIT 20
        """
    )
    
    if rows and not error:
        findings.append(
            Finding(
                title="Stored procedures sử dụng DEFINER có đặc quyền cao",
                severity="Medium",
                description="Có stored procedures/functions được định nghĩa với DEFINER là root hoặc admin.",
                recommendation="Tạo lại procedures với DEFINER có quyền hạn chế hoặc dùng SQL SECURITY INVOKER.",
                details={"count": len(rows), "examples": rows[:5]},
            )
        )
    
    # Kiểm tra views
    rows, _ = _execute(
        cursor,
        """
        SELECT TABLE_NAME, DEFINER, SECURITY_TYPE, TABLE_SCHEMA
        FROM information_schema.VIEWS
        WHERE DEFINER LIKE '%root%' OR DEFINER LIKE '%admin%'
        LIMIT 20
        """
    )
    
    if rows:
        findings.append(
            Finding(
                title="Views sử dụng DEFINER có đặc quyền cao",
                severity="Medium",
                description="Có views được định nghĩa với DEFINER là root hoặc admin.",
                recommendation="Tạo lại views với DEFINER có quyền hạn chế.",
                details={"count": len(rows), "examples": rows[:5]},
            )
        )
    
    return findings


def _check_default_authentication_plugin(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra plugin xác thực mặc định"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'default_authentication_plugin'")
    if error or not rows:
        return []
    
    plugin = rows[0]["Value"]
    _register_variable(metadata, "default_authentication_plugin", plugin)
    
    if plugin == "mysql_native_password":
        return [
            Finding(
                title="Plugin xác thực mặc định không an toàn",
                severity="Low",
                description="default_authentication_plugin đang là mysql_native_password, kém bảo mật hơn caching_sha2_password.",
                recommendation="Đặt default_authentication_plugin=caching_sha2_password trong my.cnf (MySQL 8.0+).",
                details={"default_authentication_plugin": plugin},
            )
        ]
    
    return []


def _check_binlog_format(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    """Kiểm tra binlog_format có thể gây vấn đề bảo mật"""
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'binlog_format'")
    if error or not rows:
        return []
    
    binlog_format = rows[0]["Value"]
    _register_variable(metadata, "binlog_format", binlog_format)
    
    if binlog_format.upper() == "STATEMENT":
        return [
            Finding(
                title="Binlog format STATEMENT có thể không an toàn",
                severity="Low",
                description="binlog_format=STATEMENT có thể gây inconsistency và có vấn đề bảo mật với một số functions.",
                recommendation="Sử dụng binlog_format=ROW hoặc MIXED để tăng tính nhất quán và bảo mật.",
                details={"binlog_format": binlog_format},
            )
        ]
    
    return []


def _ensure_schema_analysis(metadata: Dict[str, Any], schema: str) -> Dict[str, Any]:
    """Helper function để đảm bảo schema_analysis tồn tại"""
    if metadata.get("schema_analysis") is None:
        metadata["schema_analysis"] = {}
    if schema not in metadata["schema_analysis"]:
        metadata["schema_analysis"][schema] = {"summary": {}}
    return metadata["schema_analysis"][schema]


def _check_schema_privileges(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    schema = metadata.get("target_schema")
    if not schema:
        return []

    rows, error = _execute(
        cursor,
        """
        SELECT
            GRANTEE,
            PRIVILEGE_TYPE
        FROM information_schema.schema_privileges
        WHERE TABLE_SCHEMA = %s
        """,
        (schema,),
    )
    if error:
        _register_skip(metadata, "schema_privileges", error)
        return []

    privilege_map: Dict[str, Set[str]] = {}
    for row in rows:
        grantee = row["GRANTEE"]
        privilege_map.setdefault(grantee, set()).add(row["PRIVILEGE_TYPE"])

    high_risk = {"ALL PRIVILEGES", "GRANT OPTION", "DROP", "ALTER", "CREATE", "CREATE ROUTINE", "TRIGGER"}
    flagged: List[Dict[str, Any]] = []
    analysis = _ensure_schema_analysis(metadata, schema)
    schema_privileges: List[Dict[str, Any]] = []

    for grantee, privileges in privilege_map.items():
        if "USAGE" in privileges and len(privileges) == 1:
            schema_privileges.append(
                {
                    "user": _split_grantee(grantee)[0],
                    "host": _split_grantee(grantee)[1],
                    "privileges": sorted(privileges),
                    "grant_option": False,
                }
            )
            continue
        user, host = _split_grantee(grantee)
        grant_option = "GRANT OPTION" in privileges
        schema_privileges.append(
            {
                "user": user,
                "host": host,
                "privileges": sorted(privileges),
                "grant_option": grant_option,
            }
        )
        if "ALL PRIVILEGES" in privileges or privileges.intersection(high_risk):
            flagged.append(
                {
                    "user": user,
                    "host": host,
                    "privileges": sorted(privileges),
                }
            )

    if not flagged:
        analysis["schema_privileges"] = schema_privileges
        analysis["summary"]["schema_grantees"] = len(schema_privileges)
        return []

    analysis["schema_privileges"] = schema_privileges
    analysis["summary"]["schema_grantees"] = len(schema_privileges)

    return [
        Finding(
            title="Đặc quyền nguy hiểm trên schema được chọn",
            severity="High",
            description=f"Một số tài khoản có quyền mạnh trên schema `{schema}`.",
            recommendation="Rà soát và giới hạn quyền theo nguyên tắc tối thiểu cần thiết.",
            details={"schema": schema, "accounts": flagged},
        )
    ]


def _check_table_privileges(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    schema = metadata.get("target_schema")
    if not schema:
        return []

    rows, error = _execute(
        cursor,
        """
        SELECT
            GRANTEE,
            TABLE_NAME,
            PRIVILEGE_TYPE
        FROM information_schema.table_privileges
        WHERE TABLE_SCHEMA = %s
        """,
        (schema,),
    )
    if error:
        _register_skip(metadata, "table_privileges", error)
        return []

    table_privilege_map: Dict[str, Dict[str, Set[str]]] = {}
    for row in rows:
        grantee = row["GRANTEE"]
        table_privilege_map.setdefault(grantee, {})
        table_privilege_map[grantee].setdefault(row["TABLE_NAME"], set()).add(row["PRIVILEGE_TYPE"])

    analysis = _ensure_schema_analysis(metadata, schema)
    table_privileges: List[Dict[str, Any]] = []
    flagged: List[Dict[str, Any]] = []
    high_risk = {"ALL PRIVILEGES", "DROP", "ALTER", "GRANT OPTION"}
    dml_privs = {"INSERT", "UPDATE", "DELETE"}

    for grantee, tables in table_privilege_map.items():
        user, host = _split_grantee(grantee)
        table_entries: List[Dict[str, Any]] = []
        risky_tables: List[Dict[str, Any]] = []
        for table_name, privileges in tables.items():
            sorted_privs = sorted(privileges)
            table_entries.append({"table": table_name, "privileges": sorted_privs})

            severity = None
            if "ALL PRIVILEGES" in privileges or privileges.intersection(high_risk):
                severity = "High"
            elif len(privileges.intersection(dml_privs)) >= 2:
                severity = "Medium"

            if severity:
                risky_tables.append(
                    {
                        "table": table_name,
                        "privileges": sorted_privs,
                        "severity": severity,
                    }
                )

        table_privileges.append(
            {
                "user": user,
                "host": host,
                "tables": table_entries,
            }
        )

        if risky_tables:
            flagged.append(
                {
                    "user": user,
                    "host": host,
                    "tables": risky_tables,
                }
            )

    analysis["table_privileges"] = table_privileges
    analysis["summary"]["table_entries"] = sum(len(entry["tables"]) for entry in table_privileges)

    if not flagged:
        return []

    return [
        Finding(
            title="Bảng trong schema có quyền mạnh",
            severity="Medium",
            description=f"Một số bảng trong `{schema}` cấp quyền DML/DDL đáng chú ý.",
            recommendation="Hạn chế quyền INSERT/UPDATE/DELETE/DROP/ALTER cho đúng đối tượng hoặc tạo role riêng.",
            details={"schema": schema, "grantees": flagged},
        )
    ]


def _collect_routine_privileges(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    schema = metadata.get("target_schema")
    if not schema:
        return []

    rows, error = _execute(
        cursor,
        """
        SELECT
            GRANTEE,
            ROUTINE_NAME,
            ROUTINE_TYPE,
            PRIVILEGE_TYPE
        FROM information_schema.routine_privileges
        WHERE ROUTINE_SCHEMA = %s
        """,
        (schema,),
    )
    if error:
        _register_skip(metadata, "routine_privileges", error)
        return []

    routine_map: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for row in rows:
        grantee = row["GRANTEE"]
        routine_map.setdefault(grantee, {})
        key = (row["ROUTINE_NAME"], row["ROUTINE_TYPE"])
        routine_map[grantee].setdefault(
            key,
            {
                "name": row["ROUTINE_NAME"],
                "type": row["ROUTINE_TYPE"],
                "privileges": set(),
            },
        )["privileges"].add(row["PRIVILEGE_TYPE"])

    analysis = _ensure_schema_analysis(metadata, schema)
    routine_privileges: List[Dict[str, Any]] = []
    for grantee, routines in routine_map.items():
        user, host = _split_grantee(grantee)
        routine_privileges.append(
            {
                "user": user,
                "host": host,
                "routines": [
                    {"name": data["name"], "type": data["type"], "privileges": sorted(data["privileges"])}
                    for data in routines.values()
                ],
            }
        )

    analysis["routine_privileges"] = routine_privileges
    analysis["summary"]["routine_entries"] = sum(len(entry["routines"]) for entry in routine_privileges)
    return []