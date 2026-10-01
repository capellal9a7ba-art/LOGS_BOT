# c:\Users\MARCOS\Desktop\LOGS BOT\packager.py
import zipfile
from pathlib import Path

def create_output_archive(source_dir: Path, output_zip_path: Path) -> Path:
    """Compresses extracted items into a final organized archive for delivery."""
    output_zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file in source_dir.rglob("*"):
            if file.is_file():
                rel_path = file.relative_to(source_dir)
                zipf.write(file, arcname=str(rel_path))
    return output_zip_path
