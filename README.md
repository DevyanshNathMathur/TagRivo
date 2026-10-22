
# TagRivo
### Digital Metadata Privacy & Security Auditor

Live Application: https://tagrivo.onrender.com/

TagRivo is a Python-based cybersecurity project designed to help users identify potentially sensitive metadata in digital files before sharing them.

Images and PDF documents can contain information beyond their visible content, including device details, timestamps, location information and document properties.

TagRivo examines supported metadata fields, highlights potential privacy exposures, and provides an option to generate a cleaned copy for further review.

## Features

- Supports JPEG, PNG and PDF files.
- Checks file formats and validates uploaded content.
- Extracts supported metadata and technical file properties.
- Identifies potential privacy exposure categories.
- Calculates an explainable metadata privacy risk score.
- Displays detected fields and related explanations.
- Generates a separate sanitized file.
- Rescans the cleaned file to verify supported metadata removal.
- Provides before-and-after risk comparisons.
- Allows downloading cleaned files and JSON/CSV reports.
- Includes temporary download management and cleanup.

## Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- Metadata processing and file sanitization libraries

## Project Structure

- `app.py` — Flask web application and API endpoints.
- `tagrivo_core.py` — Metadata inspection and risk analysis.
- `tagrivo_sanitize.py` — File sanitization and verification.
- `templates/index.html` — Website interface.
- `static/css/style.css` — Website styling.
- `static/js/app.js` — Frontend interactions and API communication.
- `Devyansh_TagRivo.ipynb` — Project notebook.

## How It Works

1. The user selects a supported JPEG, PNG or PDF file.
2. TagRivo validates the file and inspects supported metadata.
3. The application displays technical details, detected exposures and a privacy risk score.
4. The user can create a separate sanitized copy.
5. TagRivo rescans the sanitized output using its supported checks.
6. The user can download the cleaned file and corresponding reports.

## Running the Application

Open a terminal in the project directory and run:

    python app.py

Open the application in a browser:

    http://127.0.0.1:5001

The required Python dependencies must be installed in the active environment.

## Important Limitations

TagRivo provides an assistive metadata privacy assessment and does not guarantee anonymity or complete file security.

A risk score of zero indicates that no privacy risks were identified by the supported metadata checks. It does not mean the file is completely free of identifying information.

Visible information such as faces, names, addresses and document text may remain after sanitization.

PDF sanitization can rebuild pages as images, potentially removing searchable text, hyperlinks, forms, digital signatures and accessibility features.

Users should independently inspect every cleaned file before sharing it.

## Authorship

**Project:** TagRivo — Digital Metadata Privacy & Security Auditor  
**Author:** Devyansh Nath Mathur

© 2026 Devyansh Nath Mathur. TagRivo. All rights reserved.
