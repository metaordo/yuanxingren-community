"""Pillow-based image CAPTCHA — 4 distorted alphanumeric chars with noise."""
from __future__ import annotations
import base64
import io
import random
import string
import secrets
import time
from dataclasses import dataclass
from PIL import Image, ImageDraw, ImageFont, ImageFilter

_CHARS = string.digits + string.ascii_uppercase  # 0-9 + A-Z, skip O/0/I/1 confusion
_CHARS = _CHARS.translate({ord(c): None for c in "O0I1"})

# In-memory store: token -> (answer, expires_at)
_store: dict[str, tuple[str, float]] = {}
_TTL = 300  # 5 minutes


@dataclass
class CaptchaOut:
    token: str
    image_b64: str


def _random_color(lo: int = 0, hi: int = 100) -> tuple[int, int, int]:
    return (random.randint(lo, hi), random.randint(lo, hi), random.randint(lo, hi))


def _draw_text(draw: ImageDraw, text: str, width: int, height: int) -> None:
    """Draw each char with random rotation and vertical offset."""
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
    except OSError:
        font = ImageFont.load_default()
    for i, ch in enumerate(text):
        x = 10 + i * 42 + random.randint(-4, 4)
        y = 8 + random.randint(-6, 6)
        img_ch = Image.new("RGBA", (50, 50), (0, 0, 0, 0))
        d = ImageDraw.Draw(img_ch)
        d.text((2, 2), ch, font=font, fill=_random_color(180, 255))
        img_ch = img_ch.rotate(random.randint(-30, 30), expand=False, fillcolor=(0, 0, 0, 0))
        draw.bitmap((x, y), img_ch.convert("RGBA"))


def _draw_noise(draw: ImageDraw, width: int, height: int) -> None:
    # Interference curves
    for _ in range(3):
        x0 = random.randint(0, width)
        y0 = random.randint(0, height)
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        draw.line([(x0, y0), (x1, y1)], fill=_random_color(120, 200), width=2)
    # Random dots
    for _ in range(150):
        x = random.randint(0, width - 1)
        y = random.randint(0, height - 1)
        draw.point((x, y), fill=_random_color(80, 200))


def generate() -> CaptchaOut:
    """Generate a new CAPTCHA image, store the answer, return token + base64."""
    width, height = 200, 70
    answer = "".join(secrets.choice(_CHARS) for _ in range(4))
    token = secrets.token_hex(16)

    # Background gradient
    img = Image.new("RGB", (width, height), (20, 22, 28))
    for y in range(height):
        r = 20 + int(y * 15 / height)
        for x in range(width):
            img.putpixel((x, y), (r, r + 2, r + 2))

    draw = ImageDraw.Draw(img)
    _draw_text(draw, answer, width, height)
    _draw_noise(draw, width, height)
    img = img.filter(ImageFilter.SMOOTH)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("ascii")

    # Clean expired entries
    now = time.time()
    for k in list(_store.keys()):
        if _store[k][1] < now:
            del _store[k]

    _store[token] = (answer.upper(), now + _TTL)
    return CaptchaOut(token=token, image_b64=b64)


def verify(token: str, answer: str) -> bool:
    """Check CAPTCHA answer. One-time use — token is consumed on match."""
    now = time.time()
    entry = _store.pop(token, None)
    if entry is None:
        return False
    correct, expires = entry
    if now > expires:
        return False
    return answer.strip().upper() == correct


def purge_token(token: str) -> None:
    _store.pop(token, None)
