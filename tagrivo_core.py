# TagRivo - Digital Metadata Privacy Auditor
# Reusable Metadata Security Inspection Engine

from io import BytesIO
from pathlib import Path
import warnings

from PIL import Image, ExifTags
import pymupdf


MAX_BYTES = 20 * 1024 * 1024
MAX_PIXELS = 20_000_000
MAX_PAGES = 50

FORMAT_BY_EXTENSION = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
    ".pdf": "PDF"
}


# Project-specific explainable scoring rules

RULES = {
    "Location Exposure": (
        {
            "gpsinfo", "gpslatitude", "gpslongitude",
            "gpslatituderef", "gpslongituderef"
        },
        45,
        "Location information may expose where a file was captured."
    ),

    "Identity Exposure": (
        {"author", "artist", "owner"},
        25,
        "Names recorded in metadata may identify a person."
    ),

    "Device Fingerprinting": (
        {
            "make", "model", "serialnumber",
            "bodyserialnumber", "cameraserialnumber"
        },
        20,
        "Device details can help correlate files or equipment."
    ),

    "Timeline Exposure": (
        {
            "datetime", "datetimeoriginal",
            "datetimedigitized", "creationdate", "moddate"
        },
        10,
        "Timestamps may reveal activity patterns."
    ),

    "Software Disclosure": (
        {"software", "creator", "producer"},
        10,
        "Software details can disclose editing or authoring tools."
    ),

    "Document Information": (
        {"title", "subject", "keywords"},
        5,
        "Document descriptors can reveal contextual information."
    )
}


class AuditInputError(ValueError):
    """Raised when an uploaded file cannot be accepted."""
    pass


def normalize_name(name):

    return "".join(
        character.lower()
        for character in str(name)
        if character.isalnum()
    )


def safe_value(value):

    if isinstance(value, bytes):
        return f"[binary value: {len(value)} bytes]"

    return str(value).replace("\x00", "")[:160]


# -------------------------------------------------------
# File Signature Validation
# -------------------------------------------------------

def identify_format(data, filename):

    extension = Path(filename).suffix.lower()
    expected = FORMAT_BY_EXTENSION.get(extension)

    if expected is None:
        raise AuditInputError(
            "Only JPEG, PNG and PDF files are supported."
        )

    if not data:
        raise AuditInputError(
            "The uploaded file is empty."
        )

    if len(data) > MAX_BYTES:
        raise AuditInputError(
            "The uploaded file exceeds 20 MB."
        )

    if data.startswith(b"\xff\xd8\xff"):
        actual = "JPEG"

    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        actual = "PNG"

    elif data.startswith(b"%PDF-"):
        actual = "PDF"

    else:
        raise AuditInputError(
            "The file signature is unrecognized."
        )

    if actual != expected:
        raise AuditInputError(
            "The extension does not match the file signature."
        )

    return actual


# -------------------------------------------------------
# EXIF GPS Coordinate Decoder
# -------------------------------------------------------

def decode_gps(gps, degrees_tag, direction_tag):

    components = gps.get(degrees_tag)

    direction = str(
        gps.get(direction_tag, "")
    ).upper()

    allowed = (
        {"N", "S"}
        if degrees_tag == 2
        else {"E", "W"}
    )

    if (
        direction not in allowed
        or not isinstance(components, (tuple, list))
        or len(components) != 3
    ):
        return None

    try:

        degrees, minutes, seconds = [
            float(component)
            for component in components
        ]

        maximum = 90 if degrees_tag == 2 else 180

        if not (
            0 <= degrees <= maximum
            and 0 <= minutes < 60
            and 0 <= seconds < 60
        ):
            return None

        coordinate = (
            degrees
            + minutes / 60
            + seconds / 3600
        )

        if coordinate > maximum:
            return None

        if direction in {"S", "W"}:
            coordinate = -coordinate

        return round(coordinate, 6)

    except (
        ValueError, ZeroDivisionError,
        TypeError, OverflowError
    ):
        return None


# -------------------------------------------------------
# JPEG and PNG Metadata Inspection
# -------------------------------------------------------

def inspect_image(data, file_type):

    metadata = {}

    with warnings.catch_warnings():

        warnings.simplefilter(
            "error",
            Image.DecompressionBombWarning
        )

        with Image.open(BytesIO(data)) as image:

            if image.format != file_type:
                raise AuditInputError(
                    "Image format verification failed."
                )

            pixels = image.width * image.height

            if pixels > MAX_PIXELS:
                raise AuditInputError(
                    "Image exceeds the 20-million-pixel limit."
                )

            image.load()

            properties = {
                "width": image.width,
                "height": image.height
            }

            exif = image.getexif()

            # Main EXIF tags
            for tag_id, value in exif.items():

                if tag_id in (34853, 34665):
                    continue

                tag_name = ExifTags.TAGS.get(
                    tag_id,
                    str(tag_id)
                )

                metadata[str(tag_name)] = safe_value(value)

            # Nested camera EXIF tags
            for tag_id, value in exif.get_ifd(34665).items():

                tag_name = ExifTags.TAGS.get(
                    tag_id,
                    str(tag_id)
                )

                metadata[str(tag_name)] = safe_value(value)

            # GPS information
            gps = exif.get_ifd(34853)

            if gps:

                metadata["GPSInfo"] = "Present"

                latitude = decode_gps(gps, 2, 1)
                longitude = decode_gps(gps, 4, 3)

                if latitude is not None:
                    metadata["GPSLatitude"] = latitude

                if longitude is not None:
                    metadata["GPSLongitude"] = longitude

            # PNG textual metadata
            if file_type == "PNG":

                for key, value in image.info.items():

                    if str(key).lower() not in {
                        "exif", "icc_profile"
                    }:

                        metadata[str(key)] = safe_value(value)

    return metadata, properties


# -------------------------------------------------------
# PDF Metadata Inspection
# -------------------------------------------------------

def inspect_pdf(data):

    with pymupdf.open(
        stream=data,
        filetype="pdf"
    ) as document:

        if document.needs_pass:
            raise AuditInputError(
                "Password-protected PDFs are not supported."
            )

        if not 1 <= document.page_count <= MAX_PAGES:
            raise AuditInputError(
                "PDF must contain 1 to 50 pages."
            )

        document.load_page(0)

        metadata = {
            str(key): safe_value(value)
            for key, value in document.metadata.items()
            if value not in (None, "")
        }

        properties = {
            "pages": document.page_count,
            "xmp_present": bool(
                document.get_xml_metadata()
            ),
            "embedded_files": document.embfile_count()
        }

    return metadata, properties


# -------------------------------------------------------
# Complete Privacy Audit
# -------------------------------------------------------

def inspect_upload(data, filename):

    file_type = identify_format(data, filename)

    try:

        if file_type in ("JPEG", "PNG"):

            metadata, properties = inspect_image(
                data,
                file_type
            )

        else:

            metadata, properties = inspect_pdf(data)

    except AuditInputError:
        raise

    except (
        OSError, ValueError, RuntimeError,
        TypeError, SyntaxError
    ) as error:

        raise AuditInputError(
            f"File parsing failed ({type(error).__name__})."
        ) from error

    # Identify meaningful metadata fields
    available_fields = {
        normalize_name(name): name
        for name, value in metadata.items()
        if value is not None and str(value).strip()
    }

    findings = []

    for category, rule in RULES.items():

        expected_fields, points, explanation = rule

        detected = sorted({
            available_fields[name]
            for name in expected_fields
            if name in available_fields
        })

        if detected:

            findings.append({
                "category": category,
                "fields": detected,
                "points": points,
                "explanation": explanation
            })

    score = min(
        100,
        sum(item["points"] for item in findings)
    )

    if score == 0:
        severity = "No Detected Risk"

    elif score < 15:
        severity = "Low"

    elif score < 40:
        severity = "Moderate"

    elif score < 70:
        severity = "High"

    else:
        severity = "Critical"

    # Create privacy-conscious metadata preview
    preview = []

    for key, value in sorted(
        metadata.items(),
        key=lambda entry: entry[0].lower()
    ):

        normalized = normalize_name(key)

        sensitive = any(
            word in normalized
            for word in (
                "gps", "latitude", "longitude",
                "author", "artist", "owner", "serial"
            )
        )

        preview.append({
            "field": key,
            "value": (
                "[hidden for privacy]"
                if sensitive
                else safe_value(value)
            )
        })

    return {
        "filename": Path(filename).name,
        "file_type": file_type,
        "size_bytes": len(data),
        "properties": properties,
        "risk_score": score,
        "risk_level": severity,
        "findings": findings,
        "metadata_preview": preview,
        "note": (
            "The score covers selected metadata fields only. "
            "Zero does not mean anonymous or safe."
        )
    }