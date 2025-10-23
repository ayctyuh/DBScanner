from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set

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
            connect_args["ssl"] = {}
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
        # Cột password_expired không tồn tại (ví dụ MariaDB cũ)
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


def _check_sql_mode_hardening(cursor: DictCursor, metadata: Dict[str, Any]) -> List[Finding]:
    rows, error = _execute(cursor, "SHOW VARIABLES LIKE 'sql_mode'")
    if error:
        _register_skip(metadata, "sql_mode", error)
        return []

    value = rows[0]["Value"] if rows else ""
    _register_variable(metadata, "sql_mode", value)
    modes = {mode.strip().upper() for mode in value.split(",") if mode}

    missing: List[str] = []
    for required in {"STRICT_TRANS_TABLES", "ERROR_FOR_DIVISION_BY_ZERO"}:
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
