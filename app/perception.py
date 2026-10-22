"""Local CPU perception. Extracted material always retains untrusted provenance."""
import hashlib
import os
import threading
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "2")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")
import cv2
from PIL import Image, ImageOps
import numpy as np

cv2.setNumThreads(2)
_OCR = None
_LOCK = threading.Lock()
MAX_BYTES = 8 * 1024 * 1024
MAX_PIXELS = 12_000_000

def inspect_image_bytes(data):
    import io
    if len(data) > MAX_BYTES:
        raise ValueError("Image must be smaller than 8 MB.")
    try:
        image = Image.open(io.BytesIO(data))
        if image.format not in {"PNG", "JPEG", "WEBP"}:
            raise ValueError("Use a PNG, JPEG or WebP image.")
        if image.width * image.height > MAX_PIXELS:
            raise ValueError("Image must contain no more than 12 million pixels.")
        image.load()
        return ImageOps.exif_transpose(image).convert("RGB")
    except (OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Image cannot be decoded safely.") from exc

def perceive_image(path):
    global _OCR
    data = Path(path).read_bytes()
    image = inspect_image_bytes(data)
    width, height = image.size
    if max(image.size) > 2200:
        image.thumbnail((2200, 2200))
    frame = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    payloads = []
    found, values, _points, _ = detector.detectAndDecodeMulti(frame)
    if found:
        payloads.extend(value for value in values if value)
    if not payloads:
        value, _points, _ = detector.detectAndDecode(frame)
        if value:
            payloads.append(value)
    with _LOCK:
        if _OCR is None:
            from rapidocr_onnxruntime import RapidOCR
            _OCR = RapidOCR(intra_op_num_threads=2, inter_op_num_threads=1)
        result, elapsed = _OCR(frame)
    items = []
    if result:
        for box, text, confidence in result:
            items.append({"text": text, "confidence": round(float(confidence), 4), "box": [[round(float(x), 1), round(float(y), 1)] for x, y in box]})
    text = "\n".join(item["text"] for item in items)
    warnings = []
    if not text:
        warnings.append("No text was recognized. This does not establish that the image is safe.")
    if any(value.startswith(("https://", "http://")) for value in payloads):
        warnings.append("Decoded URL is reported as data only. No linked page was fetched.")
    markers = ("ignore", "disregard", "assistant", "send_message", "change_destination", "instruction", "before answering")
    suspicious = [item["text"] for item in items if any(marker in item["text"].lower() for marker in markers)]
    suspicious.extend(value for value in payloads if any(marker in value.lower() for marker in markers))
    return {"ocr_text": text, "qr_payloads": list(dict.fromkeys(payloads)), "items": items, "sha256": hashlib.sha256(data).hexdigest(), "width": width, "height": height, "warnings": warnings, "signals": suspicious, "signals_limitation": "Keyword hints help inspection but do not decide whether an action is authorized and do not detect all attacks.", "engines": {"ocr": "RapidOCR/ONNX CPU", "qr": "OpenCV QRCodeDetector", "url_fetch": False}, "provenance": "untrusted scene image"}
