"""Install the pinned public RotNetR checkpoint without executing upstream code."""
import hashlib
from pathlib import Path
import subprocess
import urllib.request

URL = "https://github.com/lumina37/rotate-captcha-crack/releases/download/v0.5.1/RotNetR.7z"
ARCHIVE_SHA = "fc7fe43139475460cd9284c09169c84e12411b774542e74088fcb12b16550bbc"
MODEL_SHA = "f3546e2c91d13f3747e3b916f291f40981426374ddee7c1a50d22dc62158613b"
MEMBER = "RotNetR/250101_23_38_54_001/best.pth"


def verify(path, expected):
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError("Downloaded model does not match the pinned SHA-256")


def main():
    runtime = Path(__file__).resolve().parents[1] / ".captcha-tools"
    model = runtime / "baidu-models/RotNetR-v0.5.1.pth"
    if model.exists():
        verify(model, MODEL_SHA)
        print("RotNetR checkpoint verified")
        return
    archive = runtime / "downloads/RotNetR-v0.5.1.7z"
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        temporary = archive.with_suffix(".part")
        request = urllib.request.Request(URL, headers={"User-Agent": "SentinelDesk-model-setup"})
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as stream:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 67256687:
                    raise ValueError("Unexpected model archive size")
                stream.write(chunk)
        verify(temporary, ARCHIVE_SHA)
        temporary.replace(archive)
    verify(archive, ARCHIVE_SHA)
    model.parent.mkdir(parents=True, exist_ok=True)
    temporary = model.with_suffix(".part")
    # Extract one fixed archive member to stdout, never archive-selected paths.
    with temporary.open("wb") as stream:
        subprocess.run(["tar", "-xOf", str(archive), MEMBER], stdout=stream, check=True)
    verify(temporary, MODEL_SHA)
    temporary.replace(model)
    print("RotNetR checkpoint installed and verified")


if __name__ == "__main__":
    main()
