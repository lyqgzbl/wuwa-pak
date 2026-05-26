# wuwa-pak

`wuwa-pak` 是一个用于解析和提取鸣潮 Pak 文件的 Python 工具包。

面向离线研究、数据整理和脚本化处理场景。需要显式提供自己的 Pak 文件和 AES key；工具本身不会尝试获取密钥、发现游戏进程或自动操作游戏客户端。

## 功能

- 读取 Pak footer 和索引信息。
- 支持加密索引解密。
- 解析 Pak 条目、文件名和压缩方法。
- 提取未压缩或 Zlib 压缩的条目。
- 处理鸣潮 Pak 条目的部分加密行为。
- 提供 CLI，用于查看 Pak 信息、列出条目、提取文件和扫描 SQLite 文件。
- 提供 Python API，便于集成到自己的离线脚本中。

## 安装

从 PyPI 安装：

```bash
pip install wuwa-pak
```

从源码安装开发环境：

```bash
git clone https://github.com/lyqgzbl/wuwa-pak.git
cd wuwa-pak
uv sync --all-groups
```

## CLI 用法

查看 Pak 基本信息：

```bash
wuwa-pak info --pak path/to/file.pak --key HEX_KEY
```

列出 Pak 内文件：

```bash
wuwa-pak list --pak path/to/file.pak --key HEX_KEY
wuwa-pak list --pak path/to/file.pak --key HEX_KEY --filter .db
```

提取文件：

```bash
wuwa-pak extract --pak path/to/file.pak --key HEX_KEY --out out/
wuwa-pak extract --pak path/to/file.pak --key HEX_KEY --filter .db --out out/
```

扫描可能的 SQLite 条目：

```bash
wuwa-pak scan-sqlite --pak path/to/file.pak --key HEX_KEY
```

所有命令都必须显式传入 `--pak` 和 `--key`。`extract` 还必须显式传入 `--out` 输出目录。

## Python API

```python
from wuwa_pak.pak import PakArchive

archive = PakArchive.open("path/to/file.pak", "HEX_KEY")

for entry in archive.entries:
    print(entry.name, entry.uncompressed_size, entry.encrypted)

data = archive.extract_entry(archive.entries[0])
```

## 支持范围

当前实现专注于鸣潮 Pak 的离线解析和提取，主要覆盖：

- Pak footer 解析。
- Pak index 解析。
- full directory index 文件名解析。
- AES-ECB 解密。
- 未压缩条目提取。
- Zlib 压缩条目提取。
- 鸣潮条目编码和部分加密长度处理。

不保证支持所有 Unreal Engine Pak 版本、所有压缩算法或所有游戏的自定义 Pak 变体。

## 开发与测试

```bash
uv sync --all-groups
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv build
```

## 归因

鸣潮 Pak 条目解码和部分加密行为的实现参考了 [CUE4Parse](https://github.com/FabianFG/CUE4Parse)。CUE4Parse 是 Apache-2.0 许可的 Unreal Engine 归档解析库。

`wuwa-pak` 是独立的 Python 实现，面向离线脚本化处理场景。更多归因细节见 `NOTICE`。

## 许可证

`wuwa-pak` 使用 Apache 许可证 2.0 版。详见 `LICENSE` 和 `NOTICE`。
