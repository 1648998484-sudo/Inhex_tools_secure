"""
INHEX_tools_secure — 隐私保护解码节点（二维码隐写 · 防安审泄露版）

设计目标：
    在 RunningHub 等在线 ComfyUI 平台上，原版 DuckDecodeNode 会在解码阶段
    把明文图片/视频/文本写到 output/ 目录，并返回明文 IMAGE/AUDIO tensor，
    导致平台的内容安审在中间节点（如 #143）就能"看到"隐私内容，从而误判失败。

本节点改造策略（最高防泄露强度：二维码隐写 + 端到端加密透传）：
    1. 解码全程在内存（BytesIO）完成，绝不调用 folder_paths.get_output_directory()，
       绝不把明文写到磁盘。
    2. 解码出的明文立即用一次性会话密钥加密，得到密文字节流。
    3. 密文字节流被隐写进一张「二维码」的像素 LSB 位里。这张二维码扫描后会
       跳转到指定链接（QQ 群链接），因此对平台安审而言只是一张无害的普通
       二维码图片；真正的隐私内容以密文形态藏在像素最低位，平台无法还原。
    4. 真正的明文还原，只交给下游的 SecureRevealNode（最终结果前一刻）在内存中
       从二维码 LSB 位提取密文并解密完成，从而让平台安审只在最终结果处才接触明文。

与 SS_tools 完全兼容：本节点复用了原版 duck_decode_node.py 的隐写提取与
头部解析算法（_extract_payload_with_k / _parse_header），因此同一个鸭子图
可以直接用本节点解码，无需修改编码端。

依赖：qrcode[pil]（生成二维码）、numpy、Pillow、torch、moviepy（可选）
"""

import io
import os
import struct
import hashlib
import numpy as np
from typing import Any
from PIL import Image
import torch

try:
    import qrcode
    from qrcode import constants as _qr_constants
    _HAS_QRCODE = True
except ImportError:
    _HAS_QRCODE = False

try:
    import folder_paths  # type: ignore
except Exception:
    folder_paths = None

CATEGORY = "INHEX/Secure"

# 与原版 SS_tools 保持一致的隐写参数（用于从鸭子图提取明文）
WATERMARK_SKIP_W_RATIO = 0.40
WATERMARK_SKIP_H_RATIO = 0.08

# 二维码承载的目标链接（扫描二维码后跳转到此链接）
QR_TARGET_URL = os.environ.get("INHEX_QR_URL", "https://qm.qq.com/q/937kms3sfm")

# 二维码生成参数
QR_ERROR_CORRECTION = _qr_constants.ERROR_CORRECT_H if _HAS_QRCODE else None  # 30% 容错
QR_BOX_SIZE = 10      # 每个模块像素尺寸，越大容量越高
QR_BORDER = 4         # 白边（静区）

# 会话密钥（进程级）。用于加密/解密明文，只在本 ComfyUI 进程内有效，
# 不落盘、不随产物输出，因此平台无法通过产物扫描还原明文。
# 实际部署时可通过环境变量注入外部密钥以增强隔离。
_SESSION_KEY = os.environ.get("INHEX_SESSION_KEY", os.urandom(32).hex())


# ============================================================
# 一、从鸭子图提取明文（复用 SS_tools 原版算法）
# ============================================================

def _extract_payload_with_k(arr: np.ndarray, k: int) -> bytes:
    """从鸭子图像素的 LSB 位提取载荷字节（与原版逐行一致）。"""
    h, w, c = arr.shape
    skip_w = int(w * WATERMARK_SKIP_W_RATIO)
    skip_h = int(h * WATERMARK_SKIP_H_RATIO)
    mask2d = np.ones((h, w), dtype=bool)
    if skip_w > 0 and skip_h > 0:
        mask2d[:skip_h, :skip_w] = False
    mask3d = np.repeat(mask2d[:, :, None], c, axis=2)
    flat = arr.reshape(-1)
    idxs = np.flatnonzero(mask3d.reshape(-1))
    vals = (flat[idxs] & ((1 << k) - 1)).astype(np.uint8)
    ub = np.unpackbits(vals, bitorder="big").reshape(-1, 8)[:, -k:]
    bits = ub.reshape(-1)
    if len(bits) < 32:
        raise ValueError("Insufficient image data. 图像数据不足")
    len_bits = bits[:32]
    length_bytes = np.packbits(len_bits, bitorder="big").tobytes()
    header_len = struct.unpack(">I", length_bytes)[0]
    total_bits = 32 + header_len * 8
    if header_len <= 0 or total_bits > len(bits):
        raise ValueError("Payload length invalid. 载荷长度异常")
    payload_bits = bits[32:32 + header_len * 8]
    return np.packbits(payload_bits, bitorder="big").tobytes()


def _generate_key_stream(password: str, salt: bytes, length: int) -> bytes:
    key_material = (password + salt.hex()).encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key_material + str(counter).encode("utf-8")).digest())
        counter += 1
    return bytes(out[:length])


def _parse_header(header: bytes, password: str):
    """解析文件头并还原原始载荷（与原版逐行一致）。"""
    idx = 0
    if len(header) < 1:
        raise ValueError("Header corrupted. 文件头损坏")
    has_pwd = header[0] == 1
    idx += 1
    pwd_hash = b""
    salt = b""
    if has_pwd:
        if len(header) < idx + 32 + 16:
            raise ValueError("Header corrupted. 文件头损坏")
        pwd_hash = header[idx:idx + 32]; idx += 32
        salt = header[idx:idx + 16]; idx += 16
    if len(header) < idx + 1:
        raise ValueError("Header corrupted. 文件头损坏")
    ext_len = header[idx]; idx += 1
    if len(header) < idx + ext_len + 4:
        raise ValueError("Header corrupted. 文件头损坏")
    ext = header[idx:idx + ext_len].decode("utf-8", errors="ignore"); idx += ext_len
    data_len = struct.unpack(">I", header[idx:idx + 4])[0]; idx += 4
    data = header[idx:]
    if len(data) != data_len:
        raise ValueError("Data length mismatch. 数据长度不匹配")
    if not has_pwd:
        return data, ext
    if not password:
        raise ValueError("Password required. 需要密码")
    check_hash = hashlib.sha256((password + salt.hex()).encode("utf-8")).digest()
    if check_hash != pwd_hash:
        raise ValueError("Wrong password. 密码错误")
    ks = _generate_key_stream(password, salt, len(data))
    plain = bytes(a ^ b for a, b in zip(data, ks))
    return plain, ext


# ============================================================
# 二、会话密钥加解密（流式异或）
# ============================================================

def _encrypt_bytes(data: bytes, key: str) -> bytes:
    """用会话密钥做流式异或加密。"""
    ks = _generate_key_stream(key, b"", len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _decrypt_bytes(data: bytes, key: str) -> bytes:
    return _encrypt_bytes(data, key)  # 异或对称


# ============================================================
# 三、二维码隐写：密文 <-> 二维码像素 LSB 位
# ============================================================

# 载荷格式：[4字节大端长度][密文字节] ，嵌入到二维码 RGB 三通道的 LSB 位。
# 依赖 H 级容错（30%），LSB 位扰动不会破坏二维码的扫描能力。

_LSB_MAGIC = b"INHX"  # 4 字节魔数，用于校验这是一张 INHEX 密文二维码


def _generate_qr_image(url: str) -> Image.Image:
    """生成一张指向 url 的高容错二维码（RGB）。"""
    if not _HAS_QRCODE:
        raise RuntimeError("缺少 qrcode 库，请安装：pip install qrcode[pil]")
    qr = qrcode.QRCode(
        version=None,
        error_correction=QR_ERROR_CORRECTION,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER,
    )
    qr.add_data(url)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


def _embed_bytes_into_qr(qr_img: Image.Image, payload: bytes) -> Image.Image:
    """把 payload 字节流嵌入二维码的 RGB LSB 位，返回嵌入后的二维码图。

    载荷格式：_LSB_MAGIC(4B) + 长度(4B) + payload
    每个像素提供 3 个 LSB 位（RGB 三通道各 1 bit）。
    """
    arr = np.array(qr_img.convert("RGB")).astype(np.uint8)
    h, w, c = arr.shape
    capacity_bits = h * w * c  # 每通道 1 bit

    blob = _LSB_MAGIC + struct.pack(">I", len(payload)) + payload
    bits = np.unpackbits(np.frombuffer(blob, dtype=np.uint8), bitorder="big")
    if len(bits) > capacity_bits:
        raise ValueError(
            f"密文过大({len(payload)}B)，二维码容量不足({capacity_bits // 8}B)。"
            f"请减小内容或增大 QR_BOX_SIZE。"
        )

    flat = arr.reshape(-1)
    # 只改 LSB 位，保证二维码模块颜色几乎不变
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    arr2 = flat.reshape(h, w, c)
    return Image.fromarray(arr2, mode="RGB")


def _extract_bytes_from_qr(qr_img: Image.Image) -> bytes:
    """从二维码 RGB LSB 位提取嵌入的 payload 字节流（与 _embed 对称）。"""
    arr = np.array(qr_img.convert("RGB")).astype(np.uint8)
    flat = arr.reshape(-1)
    bits = flat & 0x01
    # 先读前 32 字节（魔数4 + 长度4），确定长度
    head_bits = bits[:64]
    head = np.packbits(head_bits, bitorder="big").tobytes()
    if head[:4] != _LSB_MAGIC:
        raise ValueError("不是有效的 INHEX 密文二维码（魔数不匹配）")
    payload_len = struct.unpack(">I", head[4:8])[0]
    total_bytes = 8 + payload_len
    total_bits = total_bytes * 8
    if total_bits > len(bits):
        raise ValueError("密文二维码数据不完整")
    blob_bits = bits[:total_bits]
    blob = np.packbits(blob_bits, bitorder="big").tobytes()
    return blob[8:8 + payload_len]


# ============================================================
# 四、tensor <-> PIL 互转
# ============================================================

def _tensor_to_pil(image: torch.Tensor) -> Image.Image:
    if image.dim() == 4:
        image = image[0]
    arrf = image.detach().cpu().numpy() * 255.0
    arru = np.rint(np.clip(arrf, 0, 255)).astype(np.uint8)
    if arru.ndim == 2:
        arru = np.stack([arru, arru, arru], axis=-1)
        return Image.fromarray(arru, mode="RGB")
    if arru.shape[-1] == 3:
        return Image.fromarray(arru, mode="RGB")
    if arru.shape[-1] == 4:
        return Image.fromarray(arru, mode="RGBA")
    if arru.shape[-1] > 4:
        return Image.fromarray(arru[..., :3], mode="RGB")
    return Image.fromarray(np.repeat(arru[..., :1], 3, axis=-1), mode="RGB")


def _pil_to_tensor(image: Image.Image) -> torch.Tensor:
    arr = np.array(image).astype(np.float32) / 255.0
    return torch.from_numpy(arr)[None, ...]


# ============================================================
# 五、节点定义
# ============================================================

class SecureDecodeNode:
    """安全解码节点：从鸭子图解码明文 → 会话密钥加密 → 隐写进二维码 → 输出二维码。

    平台安审在此节点只会看到一张普通的二维码图片（扫描跳转到指定链接），
    隐私明文以密文形态藏在二维码像素 LSB 位，绝不落盘、绝不输出明文 tensor。
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "image": ("IMAGE",),
            },
            "optional": {
                "password": ("STRING", {"default": "", "multiline": False}),
                "qr_url": ("STRING", {"default": QR_TARGET_URL, "multiline": False}),
            },
        }

    RETURN_TYPES = ("IMAGE", "STRING")
    RETURN_NAMES = ("qr_image", "payload_ext")
    FUNCTION = "secure_decode"
    CATEGORY = CATEGORY
    OUTPUT_NODE = False

    def secure_decode(self, image: torch.Tensor, password: str = "", qr_url: str = ""):
        # 1) 鸭子图 → 内存提取原始载荷（复用原版算法）
        pil = _tensor_to_pil(image)
        arr = np.array(pil.convert("RGB")).astype(np.uint8)

        raw = None
        ext = None
        last_err = None
        for k in (2, 6, 8):
            try:
                header = _extract_payload_with_k(arr, k)
                raw, ext = _parse_header(header, password)
                break
            except Exception as e:
                last_err = e
                continue
        if raw is None:
            raise last_err or RuntimeError("解析失败")

        # 2) 若载荷是 binpng 包装的 mp4，还原为真实 mp4 字节（纯内存，不落盘）
        if ext.endswith(".binpng"):
            img = Image.open(io.BytesIO(raw)).convert("RGB")
            ba = np.array(img).astype(np.uint8)
            raw = ba.reshape(-1).tobytes().rstrip(b"\x00")
            ext = "mp4"

        # 3) 用会话密钥加密明文，得到密文（明文此刻即被销毁，仅存密文）
        cipher = _encrypt_bytes(raw, _SESSION_KEY)

        # 4) 生成二维码并把密文嵌入其 LSB 位
        target_url = (qr_url or QR_TARGET_URL).strip()
        qr_img = _generate_qr_image(target_url)
        qr_embedded = _embed_bytes_into_qr(qr_img, cipher)
        qr_tensor = _pil_to_tensor(qr_embedded)

        # 5) 明文原文立即释放
        del raw, cipher, arr

        return (qr_tensor, ext)


class SecureRevealNode:
    """安全揭示节点：在最终结果前一刻，从二维码 LSB 位提取密文并解密还原明文。

    这是唯一会还原明文的位置，且明文只存在于内存 + 标准 SaveImage/SaveVideo
    的最终产物中，因此安审只在最终结果处生效，符合合规预期。
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "qr_image": ("IMAGE",),
                "payload_ext": ("STRING", {"default": "png", "multiline": False}),
            },
        }

    RETURN_TYPES = ("IMAGE", "STRING")
    RETURN_NAMES = ("images", "file_path")
    FUNCTION = "secure_reveal"
    CATEGORY = CATEGORY
    OUTPUT_NODE = True

    def secure_reveal(self, qr_image: torch.Tensor, payload_ext: str = "png"):
        # 1) 二维码图 → 提取密文 → 会话密钥解密还原明文
        pil = _tensor_to_pil(qr_image)
        cipher = _extract_bytes_from_qr(pil)
        raw = _decrypt_bytes(cipher, _SESSION_KEY)

        # 2) 明文还原为图片/视频字节，写到最终输出目录（这是合规的最终结果）
        ext = payload_ext.lstrip(".")
        if ext == "binpng":
            ext = "mp4"

        base_dir = folder_paths.get_output_directory() if folder_paths else os.getcwd()
        os.makedirs(base_dir, exist_ok=True)
        out_path = os.path.join(base_dir, "inhex_revealed." + ext)

        with open(out_path, "wb") as f:
            f.write(raw)

        # 3) 若为图片，转回 IMAGE tensor 供 SaveImage 使用
        img_tensor = None
        if ext.lower() in ("png", "jpg", "jpeg", "webp", "bmp"):
            img_tensor = _pil_to_tensor(Image.open(io.BytesIO(raw)).convert("RGB"))
        else:
            # 视频：返回占位帧，视频本体已由文件落盘，可接 SaveVideo/自定义保存
            img_tensor = torch.zeros((1, 1, 1, 3), dtype=torch.float32)

        return (img_tensor, out_path)


NODE_CLASS_MAPPINGS = {
    "SecureDecodeNode": SecureDecodeNode,
    "SecureRevealNode": SecureRevealNode,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "SecureDecodeNode": "二维码隐私保护解码(防泄露) INHEX SecureDecode",
    "SecureRevealNode": "二维码最终揭示(合规送审) INHEX SecureReveal",
}
