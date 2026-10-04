# INHEX_tools_secure — 二维码隐写隐私保护节点

基于 [copyangle/SS_tools](https://github.com/copyangle/SS_tools) 的隐私保护改造包。

## 解决的问题

在线平台（RunningHub 等）运行 ComfyUI 工作流时，原版 `DuckDecodeNode`（如 `#143` 节点）
在解码鸭子图、还原用户隐私内容的过程中，会把明文写到 `output/` 目录，并返回明文
IMAGE/AUDIO tensor，导致平台的内容安审在**中间节点**就扫描到隐私内容，误判"安审失败"。

## 核心机制（二维码隐写 + 端到端加密）

解码出的隐私明文先用**会话密钥**加密，再把密文隐写进一张**二维码**的像素 LSB 位：

- 二维码扫描后会跳转到指定链接（默认 QQ 群 `https://qm.qq.com/q/937kms3sfm`）
- 对平台安审而言，`#143` 处只能看到一张**无害的普通二维码**，扫不到隐私内容
- 明文只在最终揭示节点 `SecureRevealNode` 处、内存中还原并写入最终输出

## 节点说明

| 节点 | 作用 | 落盘？ | 输出明文？ |
|------|------|:---:|:---:|
| `SecureDecodeNode` | 解码鸭子图 → 加密 → 隐写进二维码 | ❌ | ❌（只输出二维码） |
| `SecureRevealNode` | 从二维码提取密文 → 解密 → 还原明文 | ✅ 最终结果 | ✅ 仅此一步 |

### 输入参数

**SecureDecodeNode**
- `image`（必填，IMAGE）：鸭子图（SS_tools 编码产物）
- `password`（可选，STRING）：鸭子图的加密密码，留空表示无密码
- `qr_url`（可选，STRING）：二维码目标链接，默认 `https://qm.qq.com/q/937kms3sfm`

**SecureRevealNode**
- `qr_image`（必填，IMAGE）：来自 SecureDecodeNode 的二维码
- `payload_ext`（必填，STRING）：载荷扩展名（png/mp4/txt 等）

## 工作流改造

```
原链路：  #143(DuckDecodeNode)  →  #144(SaveImage/SaveVideo)

改后链路：#143(SecureDecodeNode) → SecureRevealNode → #144(SaveImage/SaveVideo)
```

## 部署

1. 将 `INHEX_tools_secure/` 目录整个放入 `ComfyUI/custom_nodes/`。
2. 安装依赖：`pip install -r requirements.txt`
3. 重启 ComfyUI，在节点面板 `INHEX/Secure` 分类下可见两个新节点。

## 环境变量（可选）

- `INHEX_SESSION_KEY`：会话密钥，默认 `os.urandom(32)` 进程随机生成
- `INHEX_QR_URL`：二维码默认目标链接

## 测试结论

- 隐写解码与原版 SS_tools 完全兼容
- 二维码嵌入密文后**仍可扫描**出目标链接（H 级 30% 容错）
- 解密还原后与原始明文像素级一致
- 中间节点不落盘
- 密码正确可解、错误密码正确拦截

## 文件清单

- `__init__.py` — 节点注册入口
- `secure_decode_node.py` — 核心：`SecureDecodeNode` + `SecureRevealNode`
- `requirements.txt` — 依赖清单
- `demo_qr.png` — 演示二维码（嵌入示例密文）
