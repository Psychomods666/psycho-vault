import os
import secrets
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from werkzeug.utils import secure_filename

from crypto_engine import (
    InvalidPasswordError,
    InvalidVaultError,
    decrypt_bytes,
    encrypt_bytes,
    sha256_bytes,
)


BASE_DIR = Path(__file__).resolve().parent

VAULT_DIR = BASE_DIR / "vault"
OUTPUT_DIR = BASE_DIR / "output"

VAULT_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


app = Flask(__name__)

# Generate a random development secret.
# For production, set FLASK_SECRET_KEY as an environment variable.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32),
)


MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def unique_filename(directory: Path, filename: str) -> Path:
    """
    Prevent overwriting an existing file.
    """

    safe_name = secure_filename(filename)

    if not safe_name:
        safe_name = "encrypted_file"

    path = directory / safe_name

    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix

    counter = 1

    while True:
        candidate = (
            directory
            / f"{stem}_{counter}{suffix}"
        )

        if not candidate.exists():
            return candidate

        counter += 1


@app.route("/")
def index():
    return render_template(
        "index.html"
    )


@app.post("/encrypt")
def encrypt():
    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    if not uploaded_file:
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

    if len(password) < 10:
        flash(
            "Password must contain at least 10 characters.",
            "error",
        )
        return redirect(url_for("index"))

    try:
        original_name = secure_filename(
            uploaded_file.filename
        )

        if not original_name:
            flash(
                "Invalid filename.",
                "error",
            )
            return redirect(url_for("index"))

        data = uploaded_file.read()

        if not data:
            flash(
                "The selected file is empty.",
                "error",
            )
            return redirect(url_for("index"))

        encrypted = encrypt_bytes(
            data,
            original_name,
            password,
        )

        output_path = unique_filename(
            VAULT_DIR,
            original_name + ".pvault",
        )

        output_path.write_bytes(
            encrypted
        )

        fingerprint = sha256_bytes(data)

        flash(
            f"Encryption successful — {output_path.name}",
            "success",
        )

        return render_template(
            "index.html",
            result={
                "type": "encrypt",
                "filename": output_path.name,
                "size": len(encrypted),
                "sha256": fingerprint,
                "download_url": url_for(
                    "download_vault",
                    filename=output_path.name,
                ),
            },
        )

    except Exception as exc:
        app.logger.exception(
            "Encryption error"
        )

        flash(
            f"Encryption failed: {exc}",
            "error",
        )

        return redirect(url_for("index"))


@app.post("/decrypt")
def decrypt():
    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    if not uploaded_file:
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

    if not password:
        flash(
            "Password is required.",
            "error",
        )
        return redirect(url_for("index"))

    try:
        package = uploaded_file.read()

        metadata, plaintext = decrypt_bytes(
            package,
            password,
        )

        original_filename = secure_filename(
            metadata["original_filename"]
        )

        if not original_filename:
            original_filename = "decrypted_file"

        output_path = unique_filename(
            OUTPUT_DIR,
            original_filename,
        )

        output_path.write_bytes(
            plaintext
        )

        fingerprint = sha256_bytes(
            plaintext
        )

        flash(
            "Decryption and integrity verification successful.",
            "success",
        )

        return render_template(
            "index.html",
            result={
                "type": "decrypt",
                "filename": output_path.name,
                "size": len(plaintext),
                "sha256": fingerprint,
                "download_url": url_for(
                    "download_output",
                    filename=output_path.name,
                ),
            },
        )

    except InvalidPasswordError:
        flash(
            "DECRYPTION BLOCKED — wrong password or file tampering detected.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    except InvalidVaultError as exc:
        flash(
            f"Invalid vault file: {exc}",
            "error",
        )

        return redirect(
            url_for("index")
        )

    except Exception:
        app.logger.exception(
            "Decryption error"
        )

        flash(
            "Decryption failed.",
            "error",
        )

        return redirect(
            url_for("index")
        )


@app.get("/download/vault/<path:filename>")
def download_vault(filename):
    path = VAULT_DIR / secure_filename(filename)

    if not path.exists() or not path.is_file():
        return "File not found.", 404

    return send_file(
        path,
        as_attachment=True,
        download_name=path.name,
    )


@app.get("/download/output/<path:filename>")
def download_output(filename):
    path = OUTPUT_DIR / secure_filename(filename)

    if not path.exists() or not path.is_file():
        return "File not found.", 404

    return send_file(
        path,
        as_attachment=True,
        download_name=path.name,
    )


@app.errorhandler(413)
def file_too_large(error):
    flash(
        "File exceeds the 100 MB upload limit.",
        "error",
    )

    return redirect(
        url_for("index")
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )