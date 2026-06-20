from __future__ import annotations

import io
import posixpath
import shutil
import tempfile
import zipfile
from pathlib import Path


def extract_zip_bytes(file_bytes: bytes, original_name: str) -> dict:
    temp_dir = Path(tempfile.mkdtemp(prefix="infrared_zip_"))
    extracted_root = temp_dir / Path(original_name).stem
    extracted_root.mkdir(parents=True, exist_ok=True)

    file_count = 0
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as archive:
        file_members = [member.filename for member in archive.infolist() if not member.is_dir() and member.filename.strip("/")]
        common_prefix = ""
        if file_members:
            common_prefix = posixpath.commonpath(file_members).strip("/")
            if common_prefix and "." in Path(common_prefix).name:
                common_prefix = str(Path(common_prefix).parent).strip(".")
            common_prefix = common_prefix.strip("/")
        for member in archive.infolist():
            relative_name = member.filename.strip("/")
            if common_prefix and relative_name.startswith(f"{common_prefix}/"):
                relative_name = relative_name[len(common_prefix) + 1 :]
            if not relative_name:
                continue

            member_path = extracted_root / relative_name
            resolved = member_path.resolve()
            if not str(resolved).startswith(str(extracted_root.resolve())):
                continue

            if member.is_dir():
                resolved.mkdir(parents=True, exist_ok=True)
                continue

            resolved.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, resolved.open("wb") as target:
                shutil.copyfileobj(source, target)
            file_count += 1

    return {
        "temp_dir": temp_dir,
        "project_root": extracted_root,
        "source_name": original_name,
        "source_type": "zip",
        "extracted_files": file_count,
    }
