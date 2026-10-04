# INHEX_tools_secure — 二进制加密结果


## 核心机制（二维码隐写 + 端到端加密）

解码出的隐私明文先用**会话密钥**加密，再把密文隐写进一张**二维码**的像素 LSB 位：



## 部署

1. 将 `INHEX_tools_secure/` 目录整个放入 `ComfyUI/custom_nodes/`。
2. 安装依赖：`pip install -r requirements.txt`
3. 重启 ComfyUI，在节点面板 `INHEX/Secure` 分类下可见两个新节点。

## 环境变量（可选）

- `INHEX_SESSION_KEY`：会话密钥，默认 `os.urandom(32)` 进程随机生成
- `INHEX_QR_URL`：二维码默认目标链接

## 文件清单

- `__init__.py` — 节点注册入口
- `secure_decode_node.py` — 核心：`SecureDecodeNode` + `SecureRevealNode`
- `requirements.txt` — 依赖清单
- `demo_qr.png` — 演示二维码（嵌入示例密文）
