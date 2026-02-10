# FRPC Manager

一个用 Python 写的 FRPC 客户端管理工具，帮你更方便地管理 frp 内网穿透配置。

## 功能

- 生成配置文件（支持 INI/YAML/TOML/JSON）
- 启动 frpc 并自动重启（崩溃后最多重试 3 次）
- 实时查看日志，自动识别常见错误
- 配置文件备份和回滚
- 自动下载对应系统的 frpc 客户端

## 使用方法

```bash
pip install pyyaml aiofiles
python frpc.py
```

然后按菜单提示操作即可。

## 支持的系统

- Windows (amd64)
- Linux (amd64)  
- macOS (Intel/Apple Silicon)

## 依赖

- Python 3.8+
- pyyaml
- aiofiles