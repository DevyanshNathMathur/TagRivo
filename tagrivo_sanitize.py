# TagRivo - Digital Metadata Privacy Auditor
# Sanitization and Verification Engine

from datetime import datetime, timezone
from io import BytesIO, StringIO
import csv
import hashlib
import json
import math

from PIL import Image, ImageOps
import pymupdf

from tagrivo_core import AuditInputError, inspect_upload


MAX_OUTPUT_BYTES = 20 * 1024 * 1024
PAGE_PIXEL_LIMIT = 8_000_000
TOTAL_PIXEL_LIMIT = 45_000_000
PDF_SCALE = 1.5


class SanitizationError(RuntimeError):
    """Raised when sanitization or verification fails."""
    pass


# -----------------------------------------------------
# 1. IMAGE SANITIZATION
# -----------------------------------------------------

def _rebuild_image(raw, kind):

    output = BytesIO()

    with Image.open(BytesIO(raw)) as original:

        original.load()

        # Apply camera orientation before discarding EXIF.
        corrected = ImageOps.exif_transpose(original)

        try:

            preserve_alpha = kind == "PNG" and (
                "A" in corrected.getbands()
                or "transparency" in original.info
            )

            mode = "RGBA" if preserve_alpha else "RGB"

            pixels = corrected.convert(mode)

            try:

                # Construct a new image from decoded pixels.
                rebuilt = Image.new(mode, corrected.size)

                try:

                    rebuilt.paste(pixels)

                    if kind == "PNG":

                        rebuilt.save(
                            output,
                            format="PNG",
                            optimize=True
                        )

                    else:

                        rebuilt.save(
                            output,
                            format="JPEG",
                            quality=92,
                            optimize=True
                        )

                finally:
                    rebuilt.close()

            finally:
                pixels.close()

        finally:
            corrected.close()

    return output.getvalue()


# -----------------------------------------------------
# 2. PDF SANITIZATION
# -----------------------------------------------------

def _rebuild_pdf(raw):

    rebuilt = pymupdf.open()
    total_pixels = 0

    try:

        with pymupdf.open(
            stream=raw,
            filetype="pdf"
        ) as source:

            for page in source:

                rectangle = page.rect

                width = math.ceil(
                    rectangle.width * PDF_SCALE
                )

                height = math.ceil(
                    rectangle.height * PDF_SCALE
                )

                if width <= 0 or height <= 0:
                    raise SanitizationError(
                        "Invalid PDF page dimensions."
                    )

                pixels = width * height
                total_pixels += pixels

                if (
                    pixels > PAGE_PIXEL_LIMIT
                    or total_pixels > TOTAL_PIXEL_LIMIT
                ):
                    raise SanitizationError(
                        "PDF rendering exceeds the safe pixel budget."
                    )

                # Render visible PDF page content.
                pixmap = page.get_pixmap(
                    matrix=pymupdf.Matrix(
                        PDF_SCALE,
                        PDF_SCALE
                    ),
                    colorspace=pymupdf.csRGB,
                    alpha=False,
                    annots=True
                )

                picture = pixmap.tobytes(
                    "jpeg",
                    jpg_quality=82
                )

                # Insert page image into a new PDF.
                fresh_page = rebuilt.new_page(
                    width=rectangle.width,
                    height=rectangle.height
                )

                fresh_page.insert_image(
                    fresh_page.rect,
                    stream=picture
                )

        # No original document properties are copied.
        rebuilt.set_metadata({})

        return rebuilt.tobytes(
            garbage=4,
            deflate=True
        )

    finally:
        rebuilt.close()


# -----------------------------------------------------
# 3. RESIDUAL METADATA VERIFICATION
# -----------------------------------------------------

def _residual_checks(clean_bytes, kind):

    issues = []

    if kind in ("JPEG", "PNG"):

        with Image.open(BytesIO(clean_bytes)) as image:

            if len(image.getexif()) != 0:
                issues.append("EXIF tags remain.")

            if kind == "PNG":

                sensitive_keys = {
                    "author",
                    "artist",
                    "software",
                    "comment",
                    "description",
                    "xml:com.adobe.xmp"
                }

                if any(
                    str(key).lower() in sensitive_keys
                    for key in image.info
                ):
                    issues.append(
                        "Recognized PNG text metadata remains."
                    )

    else:

        with pymupdf.open(
            stream=clean_bytes,
            filetype="pdf"
        ) as pdf:

            if pdf.get_xml_metadata():
                issues.append("XMP metadata remains.")

            if pdf.embfile_count() != 0:
                issues.append("Embedded files remain.")

            fields = (
                "author",
                "title",
                "subject",
                "keywords",
                "creator",
                "producer",
                "creationDate",
                "modDate"
            )

            if any(
                pdf.metadata.get(field)
                for field in fields
            ):
                issues.append(
                    "Supported PDF properties remain."
                )

            if any(
                page.get_text().strip()
                for page in pdf
            ):
                issues.append(
                    "A selectable PDF text layer remains."
                )

    return issues


# -----------------------------------------------------
# 4. PRIVACY-AWARE REPORT BUILDER
# -----------------------------------------------------

def _report_section(audit):

    return {
        "risk_score": audit["risk_score"],
        "risk_level": audit["risk_level"],
        "findings": [
            {
                "category": item["category"],
                "points": item["points"],
                "explanation": item["explanation"]
            }
            for item in audit["findings"]
        ]
    }


# -----------------------------------------------------
# 5. END-TO-END SANITIZATION WORKFLOW
# -----------------------------------------------------

def sanitize_payload(raw, filename):

    # Validate and inspect original uploaded bytes.
    baseline = inspect_upload(raw, filename)

    original_hash = hashlib.sha256(raw).hexdigest()

    kind = baseline["file_type"]

    try:

        if kind == "PDF":
            cleaned = _rebuild_pdf(raw)

        else:
            cleaned = _rebuild_image(raw, kind)

        if not cleaned or len(cleaned) > MAX_OUTPUT_BYTES:
            raise SanitizationError(
                "The cleaned copy is empty or larger than 20 MB."
            )

        clean_name = {
            "PDF": "TagRivo_Clean.pdf",
            "PNG": "TagRivo_Clean.png",
            "JPEG": "TagRivo_Clean.jpg"
        }[kind]

        # Independently rescan the reconstructed copy.
        verified_scan = inspect_upload(
            cleaned,
            clean_name
        )

        issues = _residual_checks(cleaned, kind)

    except (AuditInputError, SanitizationError):
        raise

    except Exception as error:

        raise SanitizationError(
            "Sanitization could not complete "
            f"({type(error).__name__})."
        ) from error

    if verified_scan["risk_score"] != 0:
        issues.append(
            "Recognized privacy-risk fields remain."
        )

    # The received bytes are immutable in this workflow.
    source_bytes_unchanged = (
        hashlib.sha256(raw).hexdigest() == original_hash
    )

    if not source_bytes_unchanged:
        issues.append(
            "Input bytes changed during processing."
        )

    if issues:
        raise SanitizationError(
            "Verification needs review: "
            + "; ".join(issues)
        )

    report = {
        "project": "TagRivo",
        "generated_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "format": kind,

        "before": _report_section(baseline),
        "after": _report_section(verified_scan),

        "risk_reduction": (
            baseline["risk_score"]
            - verified_scan["risk_score"]
        ),

        "verification": {
            "status": "Verified (supported checks)",
            "input_bytes_unchanged_in_memory":
                source_bytes_unchanged,
            "residual_checks_passed": True,
            "clean_copy_rescanned": True
        },

        "limitations": [
            "Only supported metadata checks were verified; "
            "this does not prove anonymity.",

            "Visible text, faces, and other content "
            "are not anonymized.",

            "Rebuilding images can alter visual quality "
            "or color information.",

            "Rasterized PDFs lose selectable text, "
            "links, forms, and signatures."
        ]
    }

    return cleaned, kind, report


# -----------------------------------------------------
# 6. JSON REPORT EXPORT
# -----------------------------------------------------

def report_as_json(report):

    return json.dumps(
        report,
        indent=2,
        ensure_ascii=False
    ).encode("utf-8")


# -----------------------------------------------------
# 7. CSV REPORT EXPORT
# -----------------------------------------------------

def report_as_csv(report):

    output = StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow([
        "Stage",
        "Risk Score",
        "Risk Level",
        "Category",
        "Points"
    ])

    for stage in ("before", "after"):

        summary = report[stage]

        if not summary["findings"]:

            writer.writerow([
                stage,
                summary["risk_score"],
                summary["risk_level"],
                "None",
                0
            ])

        for item in summary["findings"]:

            writer.writerow([
                stage,
                summary["risk_score"],
                summary["risk_level"],
                item["category"],
                item["points"]
            ])

    return output.getvalue().encode("utf-8-sig")