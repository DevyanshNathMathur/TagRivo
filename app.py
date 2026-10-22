"""
TagRivo - Digital Metadata Privacy Auditor

Custom Flask Backend

Features:
- Secure file validation
- Metadata privacy auditing
- Risk assessment
- Metadata sanitization
- Post-sanitization verification
- JSON and CSV reports
- Temporary verified downloads
- Manual download session revocation

Local development application.
"""

# ============================================================
# 1. IMPORTS
# ============================================================

from io import BytesIO
from pathlib import Path

import secrets
import sys
import threading
import time

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file
)

from tagrivo_core import (
    AuditInputError,
    MAX_BYTES,
    inspect_upload
)

from tagrivo_sanitize import (
    SanitizationError,
    report_as_csv,
    report_as_json,
    sanitize_payload
)


# ============================================================
# 2. APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

MAX_FILE_SIZE = MAX_BYTES

app.config["MAX_CONTENT_LENGTH"] = (
    MAX_FILE_SIZE + 256 * 1024
)

# Use port 5001 to avoid connecting to an older server.
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 5001

# Temporary downloads expire after 15 minutes.
DOWNLOAD_TTL_SECONDS = 15 * 60

# Limit active temporary download sessions.
MAX_DOWNLOAD_SESSIONS = 5

# Temporary in-memory download storage.
_download_sessions = {}

# Protect concurrent access to download sessions.
_download_lock = threading.Lock()


# ============================================================
# 3. TEMPORARY SESSION MANAGEMENT
# ============================================================

def _purge_expired(now):
    """
    Remove expired download sessions.

    This function must be called while holding
    the download session lock.
    """

    for token, item in list(_download_sessions.items()):

        if item["expires"] <= now:

            del _download_sessions[token]


# ============================================================
# 4. FILE UPLOAD HELPERS
# ============================================================

def _uploaded_file():
    """
    Retrieve the uploaded file from the request.
    """

    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:

        raise AuditInputError(
            "Please select an image or PDF file."
        )

    return uploaded


def _read_upload(uploaded):
    """
    Read uploaded bytes with a strict size limit.
    """

    data = uploaded.read(MAX_FILE_SIZE + 1)

    if len(data) > MAX_FILE_SIZE:

        raise AuditInputError(
            "File exceeds the 20 MB limit."
        )

    return data


# ============================================================
# 5. HTTP SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response


# ============================================================
# 6. ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def upload_too_large(_error):

    return jsonify({
        "success": False,
        "message": (
            "Upload exceeds the permitted size."
        )
    }), 413


@app.errorhandler(404)
def unknown_route(_error):

    if request.path.startswith("/api/"):

        return jsonify({
            "success": False,
            "message": (
                "API route not found on this running server."
            ),
            "path": request.path
        }), 404

    return "Page not found", 404


# ============================================================
# 7. MAIN WEBSITE
# ============================================================

@app.get("/")
def home():

    return render_template("index.html")


# ============================================================
# 8. BACKEND HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():

    sanitize_registered = any(
        rule.rule == "/api/sanitize"
        and "POST" in rule.methods

        for rule in app.url_map.iter_rules()
    )

    return jsonify({
        "success": True,
        "service": "TagRivo",
        "port": LOCAL_PORT,
        "sanitize_route_registered": sanitize_registered
    })


# ============================================================
# 9. FILE VALIDATION API
# ============================================================

@app.post("/api/validate")
def validate_file():

    try:

        uploaded = _uploaded_file()

        data = _read_upload(uploaded)

        inspection = inspect_upload(
            data,
            uploaded.filename
        )

        kind = inspection["file_type"]

        details = inspection["properties"]

        if kind == "PDF":

            properties = {
                "Pages": details["pages"]
            }

        else:

            properties = {
                "Width": details["width"],
                "Height": details["height"]
            }

        return jsonify({
            "success": True,
            "message": "File validation completed.",
            "file_type": kind,
            "size_bytes": len(data),
            "properties": properties
        })

    except AuditInputError as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 400

    except Exception:

        app.logger.exception(
            "File validation failed"
        )

        return jsonify({
            "success": False,
            "message": (
                "File could not be safely validated."
            )
        }), 400


# ============================================================
# 10. METADATA PRIVACY AUDIT API
# ============================================================

@app.post("/api/audit")
def run_metadata_audit():

    try:

        uploaded = _uploaded_file()

        raw = _read_upload(uploaded)

        # Perform metadata inspection and risk scoring.
        report = inspect_upload(
            raw,
            uploaded.filename
        )

        return jsonify({
            "success": True,
            "report": report
        })

    except AuditInputError as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 400

    except Exception:

        app.logger.exception(
            "Metadata audit failed"
        )

        return jsonify({
            "success": False,
            "message": (
                "Metadata inspection could not be completed."
            )
        }), 500


# ============================================================
# 11. FILE SANITIZATION AND VERIFICATION API
# ============================================================

@app.post("/api/sanitize")
def sanitize_uploaded_file():

    try:

        uploaded = _uploaded_file()

        raw = _read_upload(uploaded)

        # Sanitize file and verify the cleaned output.
        clean_bytes, file_type, report = sanitize_payload(
            raw,
            uploaded.filename
        )

        # Generate downloadable security reports.
        json_bytes = report_as_json(report)

        csv_bytes = report_as_csv(report)

    except (
        AuditInputError,
        SanitizationError
    ) as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 400

    except Exception:

        app.logger.exception(
            "Sanitization failed"
        )

        return jsonify({
            "success": False,
            "message": (
                "The sanitized copy could not be verified."
            )
        }), 500

    # Generate an unpredictable download token.
    token = secrets.token_urlsafe(24)

    now = time.monotonic()

    # Store only verified output and reports.
    with _download_lock:

        _purge_expired(now)

        if (
            len(_download_sessions)
            >= MAX_DOWNLOAD_SESSIONS
        ):

            oldest = min(
                _download_sessions,
                key=lambda t: (
                    _download_sessions[t]["expires"]
                )
            )

            del _download_sessions[oldest]

        _download_sessions[token] = {
            "expires": now + DOWNLOAD_TTL_SECONDS,
            "file_type": file_type,
            "clean": clean_bytes,
            "json": json_bytes,
            "csv": csv_bytes
        }

    return jsonify({
        "success": True,
        "token": token,
        "before": report["before"],
        "after": report["after"],
        "risk_reduction": report["risk_reduction"],
        "verification": report["verification"],
        "limitations": report["limitations"],
        "expires_in_seconds": DOWNLOAD_TTL_SECONDS
    })


# ============================================================
# 12. VERIFIED FILE DOWNLOAD API
# ============================================================

@app.get("/api/download/<token>/<kind>")
def download_verified_file(token, kind):

    allowed_types = (
        "clean",
        "json",
        "csv"
    )

    if kind not in allowed_types:

        return jsonify({
            "success": False,
            "message": "Unknown download type."
        }), 404

    # Check whether the download session is still valid.
    with _download_lock:

        _purge_expired(
            time.monotonic()
        )

        stored = _download_sessions.get(token)

        if stored is None:

            return jsonify({
                "success": False,
                "message": (
                    "Download expired or unavailable. "
                    "Sanitize again."
                )
            }), 404

        data = stored[kind]

        file_type = stored["file_type"]

    # Select the correct filename and MIME type.
    if kind == "clean":

        formats = {
            "JPEG": (
                "TagRivo_Clean.jpg",
                "image/jpeg"
            ),
            "PNG": (
                "TagRivo_Clean.png",
                "image/png"
            ),
            "PDF": (
                "TagRivo_Clean.pdf",
                "application/pdf"
            )
        }

        filename, mimetype = formats[file_type]

    elif kind == "json":

        filename = "TagRivo_Audit_Report.json"

        mimetype = "application/json"

    else:

        filename = "TagRivo_Audit_Findings.csv"

        mimetype = "text/csv"

    # Serve the verified output as a downloadable file.
    return send_file(
        BytesIO(data),
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename,
        conditional=False
    )


# ============================================================
# 13. CLEAR TEMPORARY DOWNLOADS API
# STEP 6D.3 - NEW FEATURE
# ============================================================

@app.post("/api/discard/<token>")
def discard_temporary_downloads(token):
    """
    Manually revoke a temporary download session.

    The cleaned file and reports associated with the
    supplied token are removed from the active cache.

    The user's original file is not modified.

    Previously downloaded files on the user's device
    are not affected.
    """

    with _download_lock:

        # Remove expired sessions first.
        _purge_expired(
            time.monotonic()
        )

        # Remove the requested download session.
        removed = _download_sessions.pop(
            token,
            None
        )

    if removed is None:

        return jsonify({
            "success": False,
            "message": (
                "Download session not found "
                "or already expired."
            )
        }), 404

    return jsonify({
        "success": True,
        "message": (
            "Temporary cleaned file and reports "
            "were removed from the active "
            "download cache."
        )
    })


# ============================================================
# 14. APPLICATION STARTUP
# ============================================================

if __name__ == "__main__":

    # List active registered routes.
    routes = sorted(
        (
            rule.rule,
            sorted(
                rule.methods - {
                    "HEAD",
                    "OPTIONS"
                }
            )
        )

        for rule in app.url_map.iter_rules()

        if rule.rule != "/static/<path:filename>"
    )

    print(
        "\nTAGRIVO - ACTIVE WEB SERVER",
        flush=True
    )

    print(
        "Source:",
        Path(__file__).resolve(),
        flush=True
    )

    print(
        "Python:",
        sys.executable,
        flush=True
    )

    print(
        "\nRegistered routes:",
        flush=True
    )

    for route, methods in routes:

        print(
            " ",
            ", ".join(methods),
            route,
            flush=True
        )

    # Make sure critical APIs were registered.
    assert any(
        route == "/api/sanitize"
        and "POST" in methods

        for route, methods in routes
    ), "Sanitization route was not registered"

    assert any(
        route == "/api/discard/<token>"
        and "POST" in methods

        for route, methods in routes
    ), "Download revocation route was not registered"

    print(
        f"\nOpen: http://{LOCAL_HOST}:{LOCAL_PORT}",
        flush=True
    )

    print(
        f"Health: http://{LOCAL_HOST}:{LOCAL_PORT}/api/health",
        flush=True
    )

    print(
        "\nTagRivo local server starting...\n",
        flush=True
    )

    app.run(
        host=LOCAL_HOST,
        port=LOCAL_PORT,
        debug=False,
        use_reloader=False
    )