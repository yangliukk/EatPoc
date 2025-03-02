# EatPoc - 简单的POC捕获工具

## 简介

EatPoc是一个简单的模拟**mitmproxy**功能的HTTP请求捕获、记录和转发工具。

该工具全程面向大模型开发,使用DeepSeek生成主要功能代码,通过Cursor进行优化调整。由于开发方式的特殊性,可能存在一些bug或需要改进的地方。欢迎提出建议和反馈。

感谢[@flowerwitch](flowerwitch.github.io)师傅对本项目的支持。
## 功能特点

- **请求捕获与记录**：自动捕获所有HTTP/HTTPS请求并保存到本地
- **请求转发**：可选择性地将请求转发到目标服务器
- **Apache服务器伪装**：响应头默认伪装为Apache服务器
- **灵活的日志管理**：按会话组织日志，便于分析和复现
- **HTTPS支持**：可配置SSL证书实现HTTPS监听
- **自动证书生成**：可选择自动生成自签名证书

## 使用场景

非开源扫描器POC更新，想进行学习或分析。但查看流量、日志等信息需要跨部门合作。该工具将接收、转发流量并保存到本地。

- **以xpoc举例**

假设运行EatPoc.py的主机IP为：192.168.1.3，默认监听 8000端口

```bash
# 获取所有POC
python EatPoc.py 

./xpoc -t http://192.168.1.3:8000

# 扫描器需要取信息，才能打第二步POC
# 将接收到的流量转发到存在漏洞的系统上
python EatPoc.py -p 8000 -t http://target-server.com

./xpoc -t http://192.168.1.3:8000

# 转发的目标漏洞系统是HTTPS
python3 EatPoc.py --generate-cert   //生成证书
python3 EatPoc.py -p 8000 --https -t https://target-server.com

./xpoc -t https://192.168.1.3:8000  //扫描器也需填https开头

```

## 运行时截图
![image](https://github.com/user-attachments/assets/d8ac313d-7128-42fa-85d6-cc69942d1e6c)

## 安装方法

### 前置依赖

```bash
#方法一
pip install httpx httpx[http2] starlette uvicorn cryptography

#方法二
pip install --break-system-packages httpx httpx[http2] starlette uvicorn cryptography
```

### 下载项目

```bash
git clone https://github.com/yangliukk/EatPoc.git
cd EatPoc
```

## 使用方法

### 基本命令

```bash
python3 EatPoc.py [参数选项]
```

### 参数说明

| 参数 | 长参数 | 描述 | 默认值 |
|------|--------|------|--------|
| `-H` | `--host` | 监听主机地址 | `0.0.0.0` |
| `-p` | `--port` | 监听端口 | `8000` |
| `-t` | `--target` | 目标服务器地址 | 无（返回空白页面） |
| `-n` | `--name` | 设置日志目录名称 | 时间戳 |
| | `--https` | 启用HTTPS | 禁用 |
| `-v` | `--verbose` | 启用详细日志输出 | 禁用 |
| | `--generate-cert` | 生成自签名SSL证书 | 禁用 |

### 环境变量

使用HTTPS时，可通过以下环境变量指定证书和密钥：

- `EATPOC_CERT_FILE`: SSL证书文件路径
- `EATPOC_KEY_FILE`: SSL密钥文件路径

## 使用示例

### 1. 仅捕获请求（不转发）

```bash
python3 EatPoc.py -p 8000 -n Folder_Name
```

### 2. 捕获并转发请求

```bash
python3 EatPoc.py -p 8000 -t http://target-server.com -n Folder_Name
```

### 3. 启用HTTPS并自动生成证书

```bash
python3 EatPoc.py -p 8000 --https --generate-cert
```

### 4. 使用已有证书启用HTTPS

```bash
# 方法1：使用环境变量
EATPOC_CERT_FILE=你的证书路径.pem EATPOC_KEY_FILE=你的密钥路径.key python3 EatPoc.py -p 8000 --https

# 方法2：使用当前目录的cert.pem和key.pem
# 确保在当前目录有这两个文件
python3 EatPoc.py -p 8000 --https
```

### 5. 转发HTTPS请求到目标

注意：当转发HTTPS请求时，扫描工具也要设定HTTPS

```bash
python3 EatPoc.py -p 8000 --https -t https://target-server.com -n Folder_Name
```

## 日志说明

所有捕获的请求和响应将保存在 `logs/<Folder_Name>/` 目录下：

- 请求日志: `<timestamp>_<request_id>_request.txt`
- 响应日志: `<timestamp>_<request_id>_response.txt`
- 错误日志: `logs/<Folder_Name>/errors/<timestamp>_<request_id>_error.txt`

## 注意事项
- 未测转发目标为HTTP2协议是否成功
- 对于更复杂的需求可以使用**Mitmproxy**工具
- 本工具仅用于授权的安全测试和教育目的
- 使用HTTPS功能需要有效的SSL证书

## 贡献与反馈

欢迎提交issue和pull request，或通过以下方式联系我们：

- 项目地址：https://github.com/yangliukk/EatPoc
