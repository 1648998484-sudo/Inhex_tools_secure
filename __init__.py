"""
INHEX_tools_secure — 基于 copyangle/SS_tools 的隐私保护改造包（二维码隐写版）。

替换原版 DuckDecodeNode，解决在线平台（RunningHub 等）在中间节点
（如 #143）触发安审失败、泄露用户隐私内容的问题。

核心机制：
    解码出的隐私明文先用会话密钥加密，再把密文隐写进一张「二维码」的
    像素 LSB 位。二维码扫描后会跳转到指定链接（QQ 群链接），对平台安审
    而言只是一张无害的普通二维码；明文只在最终揭示节点处、内存中还原。

部署方法：
    1. 将本目录（INHEX_tools_secure）整个放入 ComfyUI/custom_nodes/ 下。
    2. 安装依赖：pip install -r requirements.txt
       （qrcode[pil]、numpy<=1.26.4、Pillow、torch，moviepy 可选，并安装 ffmpeg）。
    3. 重启 ComfyUI，在节点面板 "INHEX/Secure" 分类下可见两个新节点。

用法（关键：工作流改造）：
    原工作流：#143(DuckDecodeNode) -> #144(SaveImage/SaveVideo)

    改造后：#143(SecureDecodeNode) -> SecureRevealNode -> #144(SaveImage/SaveVideo)

    即：把原 #143 换成 SecureDecodeNode，并在它和最终保存节点之间
    插入一个 SecureRevealNode。明文只会在 SecureRevealNode 这一步、在内存中
    还原并写入最终输出，平台安审只能在最终结果处看到内容。

安全说明：
    会话密钥默认由进程随机生成（os.urandom(32)），也可通过环境变量
    INHEX_SESSION_KEY 注入。二维码目标链接默认 https://qm.qq.com/q/937kms3sfm，
    可通过节点参数 qr_url 或环境变量 INHEX_QR_URL 修改。
"""

from .secure_decode_node import (
    NODE_CLASS_MAPPINGS,
    NODE_DISPLAY_NAME_MAPPINGS,
)

WEB_DIRECTORY = "./js"

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS", "WEB_DIRECTORY"]
