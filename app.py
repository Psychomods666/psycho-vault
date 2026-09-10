```python
import io
import os
import secrets

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from crypto_engine import (
    InvalidPasswordError,
    InvalidVaultError,
    decrypt_bytes,
    encrypt_bytes,
    sha256_bytes,
)


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

# Flask session / flash-message secret.
# In Vercel, FLASK_SECRET_KEY should be set as an environment
# variable. The fallback is only for local development.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32),
)


# ============================================================
# UPLOAD LIMIT
# ============================================================

# 50 MB is a safer limit for a serverless deployment.
MAX_FILE_SIZE = 50 * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# ============================================================
# HELPERS
# ============================================================

def safe_filename(filename: str, fallback: str = "file") -> str:
    """
    Sanitize a user-supplied filename.
    """
    name = secure_filename(filename or "")

    if not name:
        return fallback

    return name


def encrypted_filename(original_filename: str) -> str:
    """
    Convert:
        secret.txt
    into:
        secret.pvault

    instead of:
        secret.txt.pvault
    """
    name = safe_filename(
        original_filename,
        "encrypted_file",
    )

    if "." in name:
        name = name.rsplit(".", 1)[0]

    return f"{name}.pvault"


def decrypted_filename(original_filename: str) -> str:
    """
    Restore the original filename safely.
    """
    return safe_filename(
        original_filename,
        "decrypted_file",
    )


# ============================================================
# HOME
# ============================================================

@app.get("/")
def index():
    return render_template("index.html")


# ============================================================
# ENCRYPT
# ============================================================

@app.post("/encrypt")
def encrypt():
    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    # --------------------------------------------------------
    # Validate upload
    # --------------------------------------------------------

    if uploaded_file is None:
        flash(
            "Please select a file.",
            "error",
        )
        return redirect(url_for("index"))

    if not uploaded_file.filename:
        flash(
            "No filename received.",
            "error",
        )
        return redirect(url_for("index"))

    # --------------------------------------------------------
    # Validate password
    # --------------------------------------------------------

    if len(password) < 10:
        flash(
            "Password must contain at least 10 characters.",
            "error",
        )
        return redirect(url_for("index"))

    try:
        # ----------------------------------------------------
        # Read file into memory
        # ----------------------------------------------------

        data = uploaded_file.read()

        if not data:
            flash(
                "The selected file is empty.",
                "error",
            )
            return redirect(url_for("index"))

        # ----------------------------------------------------
        # Secure original filename
        # ----------------------------------------------------

        original_name = safe_filename(
            uploaded_file.filename,
            "encrypted_file",
        )

        # ----------------------------------------------------
        # Calculate original SHA-256
        # ----------------------------------------------------

        fingerprint = sha256_bytes(data)

        # ----------------------------------------------------
        # Encrypt
        # ----------------------------------------------------

        encrypted = encrypt_bytes(
            data,
            original_name,
            password,
        )

        # ----------------------------------------------------
        # Final filename
        #
        # secret.txt -> secret.pvault
        # ----------------------------------------------------

        download_name = encrypted_filename(
            original_name
        )

        # ----------------------------------------------------
        # Send encrypted file directly to browser.
        #
        # IMPORTANT:
        # Nothing is permanently written to the
        # Vercel filesystem.
        # ----------------------------------------------------

        response = send_file(
            io.BytesIO(encrypted),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=download_name,
        )

        # ----------------------------------------------------
        # Useful headers
        # ----------------------------------------------------

        response.headers["X-PSYCHO-VAULT"] = "AES-256-GCM"
        response.headers["X-Original-SHA256"] = fingerprint

        return response

    except RequestEntityTooLarge:
        raise

    except Exception:
        app.logger.exception(
            "Encryption error"
        )

        flash(
            "Encryption failed. The file could not be encrypted.",
            "error",
        )

        return redirect(
            url_for("index")
        )


# ============================================================
# DECRYPT
# ============================================================

@app.post("/decrypt")
def decrypt():
    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    # --------------------------------------------------------
    # Validate upload
    # --------------------------------------------------------

    if uploaded_file is None:
        flash(
            "Please select a .pvault file.",
            "error",
        )
        return redirect(url_for("index"))

    if not uploaded_file.filename:
        flash(
            "No filename received.",
            "error",
        )
        return redirect(url_for("index"))

    # --------------------------------------------------------
    # Validate password
    # --------------------------------------------------------

    if not password:
        flash(
            "Password is required.",
            "error",
        )
        return redirect(url_for("index"))

    try:
        # ----------------------------------------------------
        # Read encrypted package
        # ----------------------------------------------------

        package = uploaded_file.read()

        if not package:
            flash(
                "The selected vault file is empty.",
                "error",
            )
            return redirect(url_for("index"))

        # ----------------------------------------------------
        # Decrypt
        #
        # crypto_engine.py performs authentication and
        # integrity verification.
        # ----------------------------------------------------

        metadata, plaintext = decrypt_bytes(
            package,
            password,
        )

        # ----------------------------------------------------
        # Recover original filename
        # ----------------------------------------------------

        original_filename = metadata.get(
            "original_filename",
            "decrypted_file",
        )

        download_name = decrypted_filename(
            original_filename
        )

        # ----------------------------------------------------
        # Verify SHA-256 again
        # ----------------------------------------------------

        calculated_hash = sha256_bytes(
            plaintext
        )

        stored_hash = metadata.get(
            "sha256",
            "",
        )

        # Failing closed:
        # If the integrity hash does not match,
        # DO NOT release the decrypted file.
        if not stored_hash:
            flash(
                "DECRYPTION BLOCKED — integrity information is missing.",
                "error",
            )
            return redirect(
                url_for("index")
            )

        if calculated_hash.lower() != stored_hash.lower():
            flash(
                "DECRYPTION BLOCKED — file integrity verification failed.",
                "error",
            )
            return redirect(
                url_for("index")
            )

        # ----------------------------------------------------
        # Send decrypted file directly to browser.
        #
        # Nothing is permanently stored on Vercel.
        # ----------------------------------------------------

        response = send_file(
            io.BytesIO(plaintext),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=download_name,
        )

        # ----------------------------------------------------
        # Security / verification headers
        # ----------------------------------------------------

        response.headers["X-PSYCHO-VAULT"] = "INTEGRITY-VERIFIED"
        response.headers["X-SHA256"] = calculated_hash

        return response

    except InvalidPasswordError:
        # ----------------------------------------------------
        # FAIL CLOSED
        #
        # Wrong password OR authentication failure /
        # tampering should never release plaintext.
        # ----------------------------------------------------

        flash(
            "DECRYPTION BLOCKED — wrong password or file tampering detected.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    except InvalidVaultError:
        # ----------------------------------------------------
        # Do not expose internal crypto details.
        # ----------------------------------------------------

        flash(
            "DECRYPTION BLOCKED — invalid or corrupted vault file.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    except RequestEntityTooLarge:
        raise

    except Exception:
        app.logger.exception(
            "Decryption error"
        )

        # Generic error = fail closed.
        flash(
            "DECRYPTION BLOCKED — the vault file could not be safely decrypted.",
            "error",
        )

        return redirect(
            url_for("index")
        )


# ============================================================
# 413 — FILE TOO LARGE
# ============================================================

@app.errorhandler(413)
def file_too_large(error):
    flash(
        "File exceeds the 50 MB upload limit.",
        "error",
    )

    return redirect(
        url_for("index")
    )


# ============================================================
# VERCEL / LOCAL ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
```
