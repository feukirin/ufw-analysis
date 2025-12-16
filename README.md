# UFW 防火墙日志分析程序

一个功能强大的 UFW 防火墙日志分析工具，用于分析防火墙日志、检测网络攻击和识别系统漏洞。

## ✨ 主要功能

- 📊 **日志解析**: 自动读取UFW日志（支持压缩历史日志）
- 🔍 **网络分析**: 自动识别本地网络结构、网关、交换机
- 🛡️ **攻击检测**: 端口扫描、暴力破解、DoS攻击、环路风暴、注入攻击等
- 🔐 **漏洞扫描**: 危险端口检测、弱认证检测、不安全协议识别
- 📈 **统计分析**: 流量统计、协议分析、IP分类统计
- 🔗 **代理分析**: 自动识别代理服务并分析代理流量
- 🎯 **设备指纹**: IP-MAC地址关联和设备识别

## 🚀 快速开始

### 安装要求

- Python 3.6+
- 仅使用 Python 标准库
- 需要读取 `/var/log/ufw.log` 的权限（通常需要 sudo）

### 使用方法

```bash
# 基本使用（推荐）
sudo python3 main.py

# 指定日志路径
sudo python3 main.py -l /path/to/ufw.log

# 导出JSON结果
sudo python3 main.py -o result.json

# 仅导出JSON，不显示详细输出
sudo python3 main.py -j -o result.json

# 其他选项
sudo python3 main.py --no-network-analysis  # 禁用网络分析
sudo python3 main.py --no-archived          # 不读取压缩日志
sudo python3 main.py --no-online-db         # 禁用在线数据库
```

### 作为模块使用

```python
from ufw_analyzer import UFWAnalyzer

analyzer = UFWAnalyzer('/var/log/ufw.log')
analyzer.analyze()
analyzer.export_json('result.json')
```

## 📋 检测能力

### 攻击检测

- **端口扫描**: 检测对多个端口的扫描行为
- **暴力破解**: 检测针对特定服务的多次失败尝试
- **DoS攻击**: 检测拒绝服务攻击（大规模/中等规模/小规模）
- **环路风暴**: 检测网络环路风暴（广播/组播环路、多MAC地址环路）
- **注入攻击**: SQL注入、XSS、命令注入等
- **中间人攻击**: 检测MITM攻击模式
- **伪装攻击**: 检测IP伪装和源路由攻击
- **漏洞扫描**: 检测针对性的漏洞扫描行为

### 漏洞扫描

- **危险端口**: 识别开放的常见漏洞端口（包含CVE信息）
- **弱认证**: 检测SSH、MySQL、PostgreSQL、RDP等服务的认证问题
- **不安全协议**: 识别Telnet、HTTP、FTP等不安全协议
- **攻击模式**: 检测DoS、暴力破解等攻击模式特征

### 检测阈值（可在 config.py 中配置）

- 端口扫描: 10个以上不同端口
- 暴力破解: 5次以上失败尝试
- DoS攻击: 200-1000次以上阻止（根据规模）
- 环路风暴: 50-2000次重复（根据置信度）
- 可疑活动: 100次以上阻止

## 📁 项目结构

```
ufw-analyse/
├── main.py                    # 主入口
├── ufw_analyzer.py            # 兼容入口
├── config.py                  # 配置管理
├── ufw_analyzer/              # 主包
│   ├── pipeline.py            # 分析流程管理器
│   ├── core/                  # 核心模块（解析、网络、处理）
│   ├── analysis/              # 分析模块（攻击、漏洞、统计、代理）
│   ├── data/                  # 数据模块（漏洞库、安全库、设备指纹）
│   ├── output/                # 输出模块
│   └── utils/                 # 工具模块
└── README.md
```

## ⚙️ 配置

所有检测阈值和配置项可在 `config.py` 中修改，包括：

- 攻击检测阈值（端口扫描、暴力破解、DoS等）
- 端口映射和服务识别
- 代理端口配置
- 漏洞数据库设置

## 📝 注意事项

1. **权限要求**: 读取系统日志文件通常需要 root 权限
2. **日志格式**: 支持标准 UFW 日志格式
3. **压缩日志**: 自动支持读取 `.gz` 格式的压缩日志
4. **性能**: 采用单次遍历优化，提高分析速度
5. **误报**: 某些检测可能存在误报，需要人工验证

## 🔄 更新日志

### v2.0.0
- ✅ 模块化重构，提高可维护性
- ✅ 统一数据处理管道，单次遍历优化
- ✅ 环路风暴检测
- ✅ MAC地址解析修复（支持14段格式）
- ✅ DoS攻击检测增强（结合设备指纹）
- ✅ 源路由攻击检测优化（排除正常NAT流量）
- ✅ 配置管理集中化

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
