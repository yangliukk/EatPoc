#!/usr/bin/env python3
import argparse
import os
import sys
import time
import signal
import json
import logging
import asyncio
from typing import Optional, Dict, Any, Union, List
from urllib.parse import urlparse
import ssl
from email.utils import formatdate  # 添加导入 formatdate 函数
import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse
from starlette.routing import Route
import uvicorn
from contextlib import asynccontextmanager
import datetime as dt  # 导入datetime并重命名为dt，避免冲突
import ipaddress

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("EatPoc")

# 全局变量
REQUEST_COUNT = 0


class ProxyForwarder:
    """代理转发器，处理请求的捕获、转发和记录"""
    
    def __init__(self, target_url: Optional[str] = None, log_dir: str = 'logs/default'):
        self.target_url = target_url
        self.log_dir = log_dir
        
        # 创建日志目录
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(os.path.join(log_dir, 'errors'), exist_ok=True)
        
        # 创建支持 HTTP/2 的异步客户端，添加更强大的 SSL 配置
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        self.client = httpx.AsyncClient(
            http2=True,  # 启用 HTTP/2 支持
            timeout=httpx.Timeout(30.0),  # 更长的超时时间
            follow_redirects=False,  # 不自动跟随重定向，保留原始行为
            verify=False,  # 忽略 SSL 证书验证以适应更多场景
            trust_env=True,  # 信任环境变量中的代理配置
        )
        
        logger.info(f"已初始化代理转发器 - 目标: {target_url or '无 (返回空白页面)'}")
    
    async def close(self):
        """关闭客户端连接"""
        if self.client and not self.client.is_closed:
            await self.client.aclose()
            logger.info("HTTP 客户端已关闭")
    
    async def handle_request(self, request: Request) -> Response:
        """处理请求：记录、转发（如有目标）并返回响应"""
        global REQUEST_COUNT
        REQUEST_COUNT += 1
        
        # 生成时间戳和唯一标识符
        timestamp = dt.datetime.now().strftime("%Y%m%d%H%M%S%f")
        request_id = f"{timestamp}_{REQUEST_COUNT}"
        
        # 捕获请求信息
        try:
            raw_request = await self._capture_request(request)
            self._save_data(request_id, 'request', raw_request)
            logger.debug(f"已记录请求 ID: {request_id}")
        except Exception as e:
            error_msg = f"捕获请求失败: {str(e)}"
            logger.error(error_msg)
            self._save_error(request_id, error_msg)
            return PlainTextResponse("内部服务器错误", status_code=500)
        
        # 如果有目标 URL，则转发请求
        if self.target_url:
            try:
                response = await self._forward_request(request)
                logger.debug(f"请求 {request_id} 已转发，状态码: {response.status_code}")
                
                # 捕获并保存响应
                raw_response = self._capture_response(response)
                self._save_data(request_id, 'response', raw_response)
                
                # 获取所有响应头：先将响应头转换为多值字典
                headers_dict = {}
                for name, value in response.headers.items():
                    name_lower = name.lower()
                    if name_lower not in headers_dict:
                        headers_dict[name_lower] = []
                    headers_dict[name_lower].append((name, value))
                
                # 创建初始响应对象，不带任何头信息
                starlette_response = Response(
                    content=response.content,
                    status_code=response.status_code,
                )
                
                # 添加所有头信息，保留原始的大小写，但跳过 server 头
                for name_lower, headers_list in headers_dict.items():
                    # 跳过服务器头，后面单独处理
                    if name_lower == 'server':
                        continue
                    
                    # 添加所有此名称的头
                    for orig_name, value in headers_list:
                        starlette_response.headers.append(orig_name, value)
                
                # 添加 Apache 服务器头
                starlette_response.headers['Server'] = 'Apache/2.4.41 (Unix)'
                
                # 确保有 Date 头
                if 'date' not in headers_dict:
                    starlette_response.headers['Date'] = formatdate(timeval=None, localtime=False, usegmt=True)
                
                return starlette_response
            except Exception as e:
                error_msg = f"转发请求失败: {str(e)}"
                logger.error(error_msg)
                self._save_error(request_id, f"{error_msg}\n\n{raw_request}")
                return PlainTextResponse("网关错误", status_code=502)
        else:
            # 无目标 URL 时返回空白响应，但不保存响应
            blank_response = self._create_blank_response()
            logger.debug(f"请求 {request_id} 返回空白响应（未保存响应）")
            
            # 使用 Apache 服务器标识
            headers = dict(blank_response.headers)
            headers['Server'] = 'Apache/2.4.41 (Unix)'
            
            return Response(
                content=blank_response.content,
                status_code=blank_response.status_code,
                headers=headers,
            )
    
    async def _capture_request(self, request: Request) -> bytes:
        """捕获 HTTP 请求的所有细节"""
        # 构建请求行
        request_line = f"{request.method} {request.url.path}"
        if request.url.query:
            request_line += f"?{request.url.query}"
        request_line += f" HTTP/{request.scope.get('http_version', '1.1')}\r\n"
        
        # 构建请求头
        headers = []
        for name, value in request.headers.items():
            headers.append(f"{name}: {value}")
        headers_str = "\r\n".join(headers)
        
        # 获取请求体
        body = await request.body()
        
        # 组合请求数据
        raw_data = f"{request_line}{headers_str}\r\n\r\n".encode() + body
        
        return raw_data
    
    async def _forward_request(self, request: Request) -> httpx.Response:
        """转发请求到目标服务器"""
        # 构建目标 URL
        path = request.url.path
        query = request.url.query
        
        # 确保正确拼接 URL
        target_url = self.target_url.rstrip('/')
        url = f"{target_url}{path}"
        if query:
            url += f"?{query}"
        
        # 处理请求头
        headers = dict(request.headers)
        
        # 设置正确的 Host 头
        host = urlparse(url).netloc
        headers['host'] = host
        
        # 读取原始请求体
        content = await request.body()
        
        # 发送请求
        try:
            response = await self.client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=content,
            )
            return response
        except httpx.TimeoutException:
            logger.warning(f"请求超时: {url}")
            raise Exception("请求超时")
        except httpx.HTTPError as e:
            logger.warning(f"HTTP 错误: {str(e)}")
            # 如果是SSL错误，提供更详细的错误信息
            if "SSL" in str(e) or "Certificate" in str(e):
                logger.error(f"SSL/TLS错误: {str(e)}")
                raise Exception(f"SSL/TLS错误 (目标站点: {host}): {str(e)}")
            raise Exception(f"HTTP 错误: {str(e)}")
        except Exception as e:
            logger.error(f"未捕获的异常: {str(e)}")
            raise
    
    def _create_blank_response(self) -> httpx.Response:
        """创建一个空白的响应对象"""
        response = httpx.Response(
            status_code=200,
            headers={
                'Content-Type': 'text/plain',
                'Content-Length': '0',
                'Server': 'Apache/2.4.41 (Unix)',
                'Date': formatdate(timeval=None, localtime=False, usegmt=True),
            },
            content=b'',
        )
        return response
    
    def _capture_response(self, response: httpx.Response) -> bytes:
        """捕获 HTTP 响应的所有细节"""
        # 构建响应行
        # 修复重复 HTTP/ 前缀问题
        # response.http_version 已经包含 HTTP/ 前缀，因此直接使用版本号
        http_version = response.http_version
        if http_version.startswith('HTTP/'):
            http_version = http_version[5:]  # 去掉 'HTTP/' 前缀
            
        status_line = f"HTTP/{http_version} {response.status_code} {response.reason_phrase}\r\n"
        
        # 构建响应头
        headers = []
        for name, value in response.headers.items():
            headers.append(f"{name}: {value}")
        headers_str = "\r\n".join(headers)
        
        # 组合响应数据
        raw_data = f"{status_line}{headers_str}\r\n\r\n".encode() + response.content
        
        return raw_data
    
    def _save_data(self, request_id: str, data_type: str, raw_data: bytes) -> None:
        """保存数据到文件"""
        filename = f"{request_id}_{data_type}.txt"
        file_path = os.path.join(self.log_dir, filename)
        
        try:
            with open(file_path, 'wb') as f:
                f.write(raw_data)
        except IOError as e:
            logger.error(f"保存 {data_type} 数据失败: {str(e)}")
    
    def _save_error(self, request_id: str, error_msg: str) -> None:
        """保存错误信息到错误日志目录"""
        filename = f"{request_id}_error.txt"
        file_path = os.path.join(self.log_dir, 'errors', filename)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(error_msg)
        except IOError as e:
            logger.error(f"保存错误信息失败: {str(e)}")

    def add_apache_signature(self, headers: Dict[str, str]) -> Dict[str, str]:
        """添加 Apache 服务器的特征头信息"""
        # 复制原始头信息
        apache_headers = headers.copy()
        
        # 设置 Server 头
        apache_headers['Server'] = 'Apache/2.4.41 (Unix)'
        
        # 添加常见的 Apache 响应头
        if 'Date' not in apache_headers:
            apache_headers['Date'] = formatdate(timeval=None, localtime=False, usegmt=True)
        
        # 可选：添加一些 Apache 特有的头信息
        # apache_headers['X-Powered-By'] = 'PHP/7.4.3'
        
        return apache_headers


@asynccontextmanager
async def lifespan(app: Starlette):
    """应用生命周期管理器"""
    # 应用启动时执行
    logger.info("服务正在启动...")
    
    # 应用运行时执行
    yield
    
    # 应用关闭时执行
    logger.info("服务正在关闭...")
    if hasattr(app.state, 'forwarder'):
        await app.state.forwarder.close()


async def catch_all(request: Request) -> Response:
    """处理所有 HTTP 请求的通用路由处理器"""
    app = request.app
    return await app.state.forwarder.handle_request(request)


def create_app(target_url: Optional[str] = None, log_dir: str = 'logs/default') -> Starlette:
    """创建 Starlette 应用实例"""
    app = Starlette(
        lifespan=lifespan,
        routes=[Route('/{path:path}', catch_all, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])]
    )
    
    # 初始化代理转发器并将其添加到应用状态
    app.state.forwarder = ProxyForwarder(target_url=target_url, log_dir=log_dir)
    
    return app


def signal_handler(sig, frame):
    """处理中断信号"""
    logger.info("收到停止信号，正在关闭服务...")
    sys.exit(0)


def print_banner(args):
    """打印启动 banner"""
    banner = r"""
███████╗ █████╗ ████████╗██████╗  ██████╗  ██████╗
██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝
█████╗  ███████║   ██║   ██████╔╝██║   ██║██║     
██╔══╝  ██╔══██║   ██║   ██╔═══╝ ██║   ██║██║     
███████╗██║  ██║   ██║   ██║     ╚██████╔╝╚██████╗
╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝  ╚═════╝
    """
    print(banner)
    print("[*] Auther : Yangliu")
    print("[*] EATPOC - 希望每个安服仔都能早一分钟吃上猪脚饭")
    print("[*] 配置信息:")
    print(f"   监听地址: {args.host}:{args.port}")
    print(f"   HTTP 版本: HTTP/1.1 + HTTP/2")
    print(f"   目标地址: {args.target or '无 (返回空白页面)'}")
    print(f"   日志目录: {args.log_dir}")
    if args.enable_https:
        print(f"   HTTPS: 已启用")
    print("\n[!] 按 Ctrl+C 停止服务")
    print("[*] 服务已启动...")


def main():
    """主函数：解析命令行参数并启动服务器"""
    parser = argparse.ArgumentParser(
        #description="EATPOC - 希望每个安服仔都能早一分钟吃上猪脚饭",
        description=r"""
███████╗ █████╗ ████████╗██████╗  ██████╗  ██████╗
██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝
█████╗  ███████║   ██║   ██████╔╝██║   ██║██║     
██╔══╝  ██╔══██║   ██║   ██╔═══╝ ██║   ██║██║     
███████╗██║  ██║   ██║   ██║     ╚██████╔╝╚██████╗
╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝  ╚═════╝

Author: Yangliu
EATPOC - 希望每个安服仔都能早一分钟吃上猪脚饭
        """,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="使用示例:\n"
               "  python3 EatPoc.py -p 8000 -t http://target.com -n Folder_Name\n"
               "  python3 EatPoc.py -p 8000 -n Folder_Name --https\n"
               "  EATPOC_CERT_FILE=cert.pem EATPOC_KEY_FILE=key.pem python3 EatPoc.py -p 8000 --https"
    )
    
    parser.add_argument('-H', '--host', default='0.0.0.0',
                      help='监听主机 (默认: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=8000,
                      help='监听端口 (默认: 8000)')
    parser.add_argument('-t', '--target',
                      help='目标服务器地址 (例如: http://example.com)')
    parser.add_argument('-n', '--name', 
                      help='日志目录名称 (默认: 使用时间戳)')
    parser.add_argument('--https', dest='enable_https', action='store_true',
                      help='启用 HTTPS (需要 cert.pem 和 key.pem 或通过环境变量设置)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='启用详细日志输出')
    parser.add_argument('--generate-cert', action='store_true',
                      help='生成自签名SSL证书 (cert.pem 和 key.pem)')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # 如果未指定名称，则使用时间戳作为日志目录名
    if not args.name:
        current_time = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.name = current_time
        logger.info(f"未指定日志目录名，使用时间戳: {current_time}")
    
    # 准备日志目录
    log_dir = os.path.join('logs', args.name)
    args.log_dir = log_dir
    
    # 生成自签名证书（如果需要）
    if args.generate_cert:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            logger.info("开始生成自签名SSL证书...")
            
            # 生成私钥
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # 生成自签名证书
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Beijing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"EatPoc"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                dt.datetime.utcnow()
            ).not_valid_after(
                dt.datetime.utcnow() + dt.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                    x509.IPAddress(ipaddress.IPv4Address('0.0.0.0'))
                ]),
                critical=False,
            ).sign(key, hashes.SHA256())
            
            # 写入证书和私钥文件
            cert_path = "cert.pem"
            key_path = "key.pem"
            
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            logger.info(f"已生成自签名证书 {cert_path} 和私钥 {key_path}")
            
            # 设置证书和密钥文件路径
            ssl_certfile = cert_path
            ssl_keyfile = key_path
            
            # 如果用户请求生成证书，则默认启用 HTTPS
            args.enable_https = True
            
        except ImportError:
            logger.error("生成证书失败: 请安装 cryptography 库 (pip install cryptography)")
            if args.enable_https:
                logger.warning("已禁用 HTTPS 模式，因为无法生成证书")
                args.enable_https = False
        except Exception as e:
            logger.error(f"生成证书时出错: {str(e)}")
            if args.enable_https:
                logger.warning("已禁用 HTTPS 模式，因为证书生成失败")
                args.enable_https = False
    
    # 配置 SSL（如果需要）
    ssl_keyfile = None
    ssl_certfile = None
    
    if args.enable_https:
        # 首先检查环境变量
        env_cert = os.environ.get("EATPOC_CERT_FILE")
        env_key = os.environ.get("EATPOC_KEY_FILE")
        
        if env_cert and env_key and os.path.exists(env_cert) and os.path.exists(env_key):
            ssl_certfile = env_cert
            ssl_keyfile = env_key
            logger.info(f"使用环境变量中的证书: {ssl_certfile} 和密钥: {ssl_keyfile}")
        # 然后检查当前目录的默认文件
        elif os.path.exists("cert.pem") and os.path.exists("key.pem"):
            ssl_certfile = "cert.pem"
            ssl_keyfile = "key.pem"
            logger.info(f"使用当前目录的默认证书和密钥文件")
        else:
            logger.warning("未找到SSL证书和密钥，已禁用HTTPS")
            args.enable_https = False
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
    # 打印启动信息
    print_banner(args)
    
    # 创建应用
    app = create_app(target_url=args.target, log_dir=log_dir)
    
    # 启动服务
    if args.enable_https:
        logger.info(f"以HTTPS模式启动服务，端口: {args.port}，证书: {ssl_certfile}，密钥: {ssl_keyfile}")
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info" if not args.verbose else "debug",
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile,
            http="h11",  # 使用 h11 实现 HTTP/1.1
            timeout_keep_alive=5,  # 长连接保持时间
            log_config={
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "default": {
                        "()": "uvicorn.logging.DefaultFormatter",
                        "fmt": "%(levelprefix)s %(message)s",
                        "use_colors": False,
                    },
                    "access": {
                        "()": "uvicorn.logging.AccessFormatter",
                        "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
                        "use_colors": False,
                    },
                },
                "handlers": {
                    "default": {
                        "formatter": "default",
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stderr",
                    },
                    "access": {
                        "formatter": "access",
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stdout",
                    },
                },
                "loggers": {
                    "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
                    "uvicorn.error": {"level": "INFO"},
                    "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
                },
            },
        )
    else:
        logger.info(f"以HTTP模式启动服务，端口: {args.port}")
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info" if not args.verbose else "debug",
            http="h11",  # 使用 h11 实现 HTTP/1.1
            timeout_keep_alive=5,  # 长连接保持时间
            log_config={
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "default": {
                        "()": "uvicorn.logging.DefaultFormatter",
                        "fmt": "%(levelprefix)s %(message)s",
                        "use_colors": False,
                    },
                    "access": {
                        "()": "uvicorn.logging.AccessFormatter",
                        "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
                        "use_colors": False,
                    },
                },
                "handlers": {
                    "default": {
                        "formatter": "default",
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stderr",
                    },
                    "access": {
                        "formatter": "access",
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stdout",
                    },
                },
                "loggers": {
                    "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
                    "uvicorn.error": {"level": "INFO"},
                    "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
                },
            },
        )


if __name__ == '__main__':
    main()
