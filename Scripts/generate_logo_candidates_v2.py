#!/usr/bin/env python3
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Resources" / "DMGBackgroundSource.png"
OUT = ROOT / "Resources" / "logo-candidates-v2"
SIZE = 1024
SCALE = 3
CANVAS = SIZE * SCALE


def c(v: float) -> int:
    return int(v * SCALE)


def font(size: int) -> ImageFont.FreeTypeFont:
    for path in [
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/PingFang.ttc",
    ]:
        try:
            return ImageFont.truetype(path, size=size)
        except Exception:
            continue
    return ImageFont.load_default()


def rounded_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle((0, 0, size, size), radius=radius, fill=255)
    return mask


def source_crop(box: tuple[int, int, int, int]) -> Image.Image:
    source = Image.open(SOURCE).convert("RGB")
    crop = source.crop(box).resize((CANVAS, CANVAS), Image.Resampling.LANCZOS).convert("RGBA")
    return crop.filter(ImageFilter.GaussianBlur(c(0.8)))


def add_base_finish(img: Image.Image, darkness: int = 64) -> Image.Image:
    overlay = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, darkness))
    img = Image.alpha_composite(img, overlay)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((c(18), c(18), c(1006), c(1006)), radius=c(218), outline=(225, 246, 255, 80), width=c(3))
    d.arc((c(58), c(48), c(966), c(966)), 218, 326, fill=(125, 228, 255, 70), width=c(3))
    d.arc((c(78), c(68), c(946), c(944)), 222, 318, fill=(255, 218, 142, 38), width=c(2))
    return img


def glow(draw: ImageDraw.ImageDraw, x: int, y: int, r: int, color, alpha=100) -> None:
    for step in range(20, 0, -1):
        rr = r * step / 20
        a = int(alpha * (step / 20) ** 2)
        draw.ellipse((x - rr, y - rr, x + rr, y + rr), fill=(*color, a))


def route(draw: ImageDraw.ImageDraw, points, color=(88, 222, 255), width=4, alpha=190) -> None:
    for extra, a in [(22, 15), (12, 28), (5, 68)]:
        draw.line(points, fill=(*color, a), width=c(width) + extra, joint="curve")
    draw.line(points, fill=(*color, alpha), width=c(width), joint="curve")


def node(draw: ImageDraw.ImageDraw, x: int, y: int, r: int, color=(92, 225, 255), hot=False) -> None:
    glow(draw, x, y, c(r * (5 if hot else 3)), color, 90 if hot else 52)
    draw.ellipse((x - c(r), y - c(r), x + c(r), y + c(r)), fill=(*color, 238))
    draw.ellipse((x - c(max(2, r * 0.35)), y - c(max(2, r * 0.35)), x + c(max(2, r * 0.35)), y + c(max(2, r * 0.35))), fill=(255, 255, 255, 240))


def moon(draw: ImageDraw.ImageDraw, x: int, y: int, r: int, alpha=235) -> None:
    for i in range(r, 0, -2):
        t = i / r
        shade = int(238 - 58 * t)
        draw.ellipse((x - c(i), y - c(i), x + c(i), y + c(i)), fill=(shade, shade + 6, min(255, shade + 18), alpha))
    for dx, dy, rr, a in [(-20, -14, 9, 34), (22, -22, 6, 30), (24, 18, 12, 30), (-8, 28, 7, 24)]:
        draw.ellipse((x + c(dx - rr), y + c(dy - rr), x + c(dx + rr), y + c(dy + rr)), fill=(90, 112, 134, a))


def earth_rim(draw: ImageDraw.ImageDraw, box, alpha=230) -> None:
    x0, y0, x1, y1 = [c(v) for v in box]
    draw.ellipse((x0, y0, x1, y1), outline=(132, 230, 255, alpha), width=c(5))
    draw.arc((x0 - c(20), y0 + c(20), x1 + c(20), y1 + c(10)), 204, 330, fill=(255, 214, 132, 95), width=c(3))


def icon_frame(layer: Image.Image) -> Image.Image:
    mask = rounded_mask(CANVAS, c(218))
    layer.putalpha(mask)
    shadow = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sd.rounded_rectangle((c(32), c(42), c(992), c(1002)), radius=c(214), fill=(0, 0, 0, 96))
    shadow = shadow.filter(ImageFilter.GaussianBlur(c(24)))
    out = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    out.alpha_composite(shadow)
    out.alpha_composite(layer)
    return out.resize((SIZE, SIZE), Image.Resampling.LANCZOS)


def option_a() -> Image.Image:
    img = add_base_finish(source_crop((0, 260, 940, 940)), 48)
    d = ImageDraw.Draw(img)
    moon(d, c(710), c(260), 58)
    earth_rim(d, (-190, 565, 620, 1375), 180)
    route(d, [(c(185), c(725)), (c(332), c(540)), (c(545), c(420)), (c(710), c(318))], width=3)
    for p in [(185, 725), (332, 540), (545, 420), (710, 318), (810, 610), (622, 705)]:
        node(d, c(p[0]), c(p[1]), 9, hot=p in [(332, 540), (810, 610)])
    return icon_frame(img)


def option_b() -> Image.Image:
    img = add_base_finish(source_crop((460, 130, 1420, 900)), 60)
    d = ImageDraw.Draw(img)
    glow(d, c(512), c(512), c(330), (72, 215, 255), 58)
    for r, a in [(302, 54), (232, 84), (158, 118)]:
        d.ellipse((c(512 - r), c(512 - r), c(512 + r), c(512 + r)), outline=(124, 230, 255, a), width=c(4))
    route(d, [(c(220), c(620)), (c(370), c(462)), (c(548), c(398)), (c(806), c(470))], (255, 218, 133), 3, 180)
    d.rounded_rectangle((c(458), c(268), c(566), c(748)), radius=c(52), fill=(7, 20, 34, 218), outline=(174, 242, 255, 152), width=c(5))
    d.line((c(512), c(236), c(512), c(780)), fill=(120, 235, 255, 150), width=c(4))
    moon(d, c(512), c(512), 70, 200)
    return icon_frame(img)


def option_c() -> Image.Image:
    img = add_base_finish(source_crop((0, 120, 920, 860)), 42)
    d = ImageDraw.Draw(img)
    earth_rim(d, (-255, 550, 690, 1495), 230)
    route(d, [(c(128), c(790)), (c(270), c(604)), (c(484), c(510)), (c(804), c(340))], width=4, alpha=205)
    route(d, [(c(168), c(620)), (c(350), c(462)), (c(630), c(596)), (c(874), c(520))], (255, 210, 128), 3, 150)
    for x, y, hot in [(128, 790, True), (270, 604, False), (484, 510, True), (804, 340, False), (630, 596, True), (874, 520, False)]:
        node(d, c(x), c(y), 10, hot=hot)
    moon(d, c(780), c(252), 54, 225)
    return icon_frame(img)


def option_d() -> Image.Image:
    img = add_base_finish(source_crop((220, 40, 1220, 930)), 68)
    d = ImageDraw.Draw(img)
    moon(d, c(512), c(438), 142, 235)
    for angle in range(205, 510, 32):
        rad = math.radians(angle)
        x = c(512 + math.cos(rad) * 296)
        y = c(438 + math.sin(rad) * 218)
        node(d, x, y, 7, hot=angle in [269, 397])
    d.ellipse((c(206), c(212), c(818), c(664)), outline=(96, 222, 255, 68), width=c(3))
    route(d, [(c(275), c(665)), (c(512), c(438)), (c(760), c(278))], width=4)
    route(d, [(c(196), c(390)), (c(512), c(438)), (c(840), c(584))], (255, 214, 132), 2, 145)
    return icon_frame(img)


def option_e() -> Image.Image:
    img = add_base_finish(source_crop((620, 150, 1600, 940)), 72)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((c(252), c(240), c(772), c(784)), radius=c(142), fill=(236, 249, 255, 24), outline=(198, 235, 248, 82), width=c(3))
    for pts, color in [
        ([(314, 665), (456, 525), (588, 584), (720, 380)], (86, 226, 255)),
        ([(330, 384), (478, 465), (612, 332), (738, 474)], (255, 215, 128)),
    ]:
        route(d, [(c(x), c(y)) for x, y in pts], color, 4 if color[0] < 100 else 3, 185)
        for i, (x, y) in enumerate(pts):
            node(d, c(x), c(y), 10, color, hot=i in [1, 2])
    moon(d, c(512), c(512), 72, 232)
    return icon_frame(img)


def option_f() -> Image.Image:
    img = add_base_finish(source_crop((80, 0, 1040, 880)), 54)
    d = ImageDraw.Draw(img)
    moon(d, c(306), c(240), 70, 230)
    earth_rim(d, (-240, 650, 740, 1630), 168)
    # Fine Earth-Moon tether as a nod to the product name, deliberately light.
    route(d, [(c(305), c(306)), (c(358), c(440)), (c(462), c(588))], width=2, alpha=115)
    for p in [(305, 306), (358, 440), (462, 588), (602, 482), (750, 390), (820, 650)]:
        node(d, c(p[0]), c(p[1]), 8, hot=p in [(462, 588), (750, 390)])
    route(d, [(c(188), c(740)), (c(462), c(588)), (c(820), c(650))], (255, 212, 128), 3, 155)
    route(d, [(c(210), c(620)), (c(602), c(482)), (c(850), c(316))], width=3, alpha=170)
    return icon_frame(img)


def write_sheet(items: list[tuple[str, Image.Image]]) -> Image.Image:
    thumb = 260
    pad = 34
    label_h = 48
    sheet = Image.new("RGB", (pad + 3 * (thumb + pad), pad + 2 * (thumb + label_h + pad)), (232, 236, 241))
    d = ImageDraw.Draw(sheet)
    f = font(28)
    for idx, (label, img) in enumerate(items):
        col = idx % 3
        row = idx // 3
        x = pad + col * (thumb + pad)
        y = pad + row * (thumb + label_h + pad)
        thumb_img = img.resize((thumb, thumb), Image.Resampling.LANCZOS)
        sheet.paste(thumb_img, (x, y), thumb_img)
        tw = d.textlength(label, font=f)
        d.text((x + (thumb - tw) / 2, y + thumb + 12), label, font=f, fill=(23, 30, 39))
    return sheet


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    makers = [
        ("A", option_a),
        ("B", option_b),
        ("C", option_c),
        ("D", option_d),
        ("E", option_e),
        ("F", option_f),
    ]
    items = []
    for label, maker in makers:
        img = maker()
        path = OUT / f"logo-{label.lower()}.png"
        img.save(path)
        print(path)
        items.append((label, img))
    sheet = write_sheet(items)
    sheet_path = OUT / "logo-contact-sheet.png"
    sheet.save(sheet_path, quality=96)
    print(sheet_path)


if __name__ == "__main__":
    main()
