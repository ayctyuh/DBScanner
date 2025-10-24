import argparse
import os
from types import SimpleNamespace

from flask import Flask, render_template, request

from scanner import SEVERITY_ORDER, MySQLScanError, scan_mysql


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = "change-me"

    @app.route("/", methods=["GET", "POST"])
    def index():
        defaults = {
            "host": "localhost",
            "port": "",
            "username": "",
            "password": "",
            "use_ssl": False,
        }

        if request.method == "POST":
            connection_details = {
                "host": request.form.get("host", "localhost"),
                "port": int(request.form.get("port", 3306)),
                "user": request.form.get("username", ""),
                "password": request.form.get("password", ""),
                "use_ssl": request.form.get("use_ssl") == "on",
            }

            try:
                findings, metadata = scan_mysql(connection_details)
                severity_levels = list(SEVERITY_ORDER.keys())
                return render_template(
                    "results.html",
                    findings=findings,
                    metadata=metadata,
                    connection_details=SimpleNamespace(**connection_details),
                    severity_levels=severity_levels,
                )
            except MySQLScanError as exc:
                form_defaults = {
                    "host": connection_details["host"],
                    "port": connection_details["port"],
                    "username": connection_details["user"],
                    "password": connection_details["password"],
                    "use_ssl": connection_details["use_ssl"],
                }
                return render_template(
                    "index.html",
                    defaults=form_defaults,
                    error_message="Không thể kết nối tới database, vui lòng thử lại.",
                    error_details=str(exc),
                )

        return render_template("index.html", defaults=defaults)

    return app


app = create_app()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DBScanner MySQL web interface")
    parser.add_argument("--host", default=os.environ.get("DBSCANNER_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DBSCANNER_PORT", 5000)))
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.environ.get("DBSCANNER_DEBUG", "0") == "1",
        help="Enable Flask debug/auto-reload mode",
    )
    args = parser.parse_args()

    app.run(host=args.host, port=args.port, debug=args.debug)
