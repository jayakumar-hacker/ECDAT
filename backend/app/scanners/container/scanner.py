"""
Container scanner (MVP).

Performs *static* inspection of Dockerfiles and container build contexts:
base image, installed packages relevant to crypto, and copied
certificates/binaries (delegated to the certificate/binary scanners).

Does not require or use the Docker daemon, and never pulls, builds, or
executes any image or container.
"""
import os
import re
from app.scanners.dependency.scanner import _parse_dockerfile
from app.scanners.certificate.scanner import scan_certificates
from app.scanners.binary.scanner import scan_binaries


def _parse_base_image(dockerfile_path: str) -> list[str]:
    images = []
    with open(dockerfile_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"^\s*FROM\s+([^\s]+)", line, re.IGNORECASE)
            if m:
                images.append(m.group(1))
    return images


def scan_containers(root: str, errors: list) -> dict:
    from app.core.config import settings
    dockerfiles = []
    if os.path.isfile(root):
        if os.path.basename(root) in ("Dockerfile",) or root.endswith(".dockerfile"):
            dockerfiles = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in settings.SCAN_EXCLUDED_DIRS and not d.startswith(".")]
            for fn in filenames:
                if fn == "Dockerfile" or fn.endswith(".dockerfile"):
                    dockerfiles.append(os.path.join(dirpath, fn))

    base_images = []
    crypto_packages = []
    for df in dockerfiles:
        try:
            base_images.extend(_parse_base_image(df))
            crypto_packages.extend(_parse_dockerfile(df))
        except Exception as e:
            errors.append({"scanner": "container", "level": "error", "message": str(e), "file": df})

    certs = scan_certificates(root, errors) if os.path.isdir(root) else []
    binaries = scan_binaries(root, errors) if os.path.isdir(root) else []

    return {
        "dockerfiles_found": dockerfiles,
        "base_images": base_images,
        "crypto_packages": crypto_packages,
        "certificates": certs,
        "binaries": binaries,
    }
