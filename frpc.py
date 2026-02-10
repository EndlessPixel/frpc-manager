import os, sys, re, json, tomllib, yaml, shutil, zipfile, tarfile, platform, subprocess, tempfile, threading, traceback, logging, asyncio, aiofiles, hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.request import urlretrieve
from urllib.error import URLError
from datetime import datetime
from pathlib import Path

# ======================== 基础配置 ========================
# 支持的配置文件类型
SUPPORTED_CONFIG_TYPES = ['.ini', '.yml', '.yaml', '.toml', '.json']
# FRPC版本和下载地址
FRPC_VERSION = "0.67.0"
FRPC_DOWNLOAD_URLS = {
    "windows_amd64": f"https://github.com/fatedier/frp/releases/download/v{FRPC_VERSION}/frp_{FRPC_VERSION}_windows_amd64.zip",
    "linux_amd64": f"https://github.com/fatedier/frp/releases/download/v{FRPC_VERSION}/frp_{FRPC_VERSION}_linux_amd64.tar.gz",
    "darwin_amd64": f"https://github.com/fatedier/frp/releases/download/v{FRPC_VERSION}/frp_{FRPC_VERSION}_darwin_amd64.tar.gz",
    "darwin_arm64": f"https://github.com/fatedier/frp/releases/download/v{FRPC_VERSION}/frp_{FRPC_VERSION}_darwin_arm64.tar.gz"
}
# 配置模板
CONFIG_TEMPLATES = {
    "默认TCP代理": """[common]
server_addr = {server_ip}
server_port = {server_port}
token = {token}

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = {remote_port}
""",
    "HTTP反向代理": """[common]
server_addr = {server_ip}
server_port = {server_port}
token = {token}

[web]
type = http
local_ip = 127.0.0.1
local_port = 80
custom_domains = {domain}
""",
    "UDP代理(游戏)": """[common]
server_addr = {server_ip}
server_port = {server_port}
token = {token}

[game]
type = udp
local_ip = 127.0.0.1
local_port = {local_port}
remote_port = {remote_port}
"""
}
# INI语法高亮规则
SYNTAX_RULES = {
    'section': re.compile(r'\[.*?\]'),
    'key': re.compile(r'(\w+)\s*='),
    'comment': re.compile(r'#.*'),
    'string': re.compile(r'"[^"]*"|\'[^\']*\''),
    'number': re.compile(r'\b\d+\b')
}
# 错误分析规则
ERROR_ANALYSIS_RULES = [
    {
        'pattern': r'lookup (.+) on (.+):53: no such host',
        'type': 'DNS解析失败',
        'description': '域名解析失败，无法找到指定的frp服务器域名',
        'solutions': [
            '检查frp服务器域名是否正确',
            '确认本地DNS配置是否正常',
            '尝试使用服务器IP地址代替域名',
            '检查网络连接和DNS服务器可用性'
        ]
    },
    {
        'pattern': r'dial tcp (.+): connect: connection refused',
        'type': '连接被拒绝',
        'description': '无法连接到frp服务器指定端口，服务器可能未启动或端口未开放',
        'solutions': [
            '检查frp服务器是否正常运行',
            '确认server_port配置是否正确',
            '检查服务器防火墙/安全组是否开放该端口',
            '验证服务器IP地址是否正确'
        ]
    },
    {
        'pattern': r'no route to host',
        'type': '无路由到主机',
        'description': '网络不通，无法访问frp服务器',
        'solutions': [
            '检查本地网络连接',
            '验证服务器IP地址是否可达 (ping测试)',
            '检查防火墙/路由器设置',
            '确认服务器是否在线'
        ]
    },
    {
        'pattern': r'authentication failed',
        'type': '认证失败',
        'description': 'token验证失败，客户端与服务器token不匹配',
        'solutions': [
            '检查common配置中的token是否正确',
            '确认frp服务器端的token配置',
            'token区分大小写，请检查拼写'
        ]
    },
    {
        'pattern': r'address already in use',
        'type': '端口被占用',
        'description': '本地端口已被其他程序占用',
        'solutions': [
            '更换local_port为未被占用的端口',
            '查找并关闭占用该端口的程序',
            '使用netstat -ano (Windows) 或 lsof -i:端口号 (Linux) 查看端口占用'
        ]
    },
    {
        'pattern': r'remote port (.+) is already used',
        'type': '远程端口已被占用',
        'description': '指定的远程端口已被服务器上其他服务占用',
        'solutions': [
            '更换remote_port为其他未被占用的端口',
            '联系frp服务器管理员确认端口使用情况',
            '检查端口是否在服务器防火墙/安全组中开放'
        ]
    },
    {
        'pattern': r'permission denied',
        'type': '权限不足',
        'description': '没有足够的权限绑定端口或运行程序',
        'solutions': [
            '使用管理员/root权限运行frpc',
            '避免使用1024以下的特权端口',
            '检查文件/目录访问权限'
        ]
    },
    {
        'pattern': r'context deadline exceeded',
        'type': '连接超时',
        'description': '连接frp服务器超时',
        'solutions': [
            '检查网络延迟和稳定性',
            '增加连接超时时间配置',
            '确认服务器是否在公网可访问',
            '检查MTU设置是否合适'
        ]
    }
]

# ======================== 增强的验证规则 ========================
VALIDATION_RULES = {
    'server_addr': {
        'pattern': r'^(\d{1,3}\.){3}\d{1,3}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
        'error': '无效的IP地址或域名格式',
        'required': True
    },
    'server_port': {
        'range': (1, 65535),
        'error': '端口必须在1-65535之间',
        'required': True
    },
    'token': {
        'min_length': 1,
        'error': 'token不能为空（如果服务器配置了认证）',
        'required': False
    },
    'local_port': {
        'range': (1, 65535),
        'error': '本地端口必须在1-65535之间',
        'required': True
    },
    'remote_port': {
        'range': (1, 65535),
        'error': '远程端口必须在1-65535之间',
        'required': True
    },
    'local_ip': {
        'pattern': r'^(\d{1,3}\.){3}\d{1,3}$|^localhost$',
        'error': '无效的本地IP地址格式',
        'required': True,
        'default': '127.0.0.1'
    }
}

# ======================== YAML Schema 验证 ========================
FRPC_SCHEMA = {
    'type': 'object',
    'required': ['common'],
    'properties': {
        'common': {
            'type': 'object',
            'required': ['server_addr', 'server_port'],
            'properties': {
                'server_addr': {'type': 'string'},
                'server_port': {'type': 'integer', 'minimum': 1, 'maximum': 65535},
                'token': {'type': 'string'},
                'protocol': {'type': 'string', 'enum': ['tcp', 'kcp', 'websocket']},
                'log_level': {'type': 'string', 'enum': ['trace', 'debug', 'info', 'warn', 'error']}
            }
        }
    }
}

# ======================== 日志配置 ========================
def setup_logging():
    """配置结构化日志"""
    # 创建日志目录
    log_dir = Path("frpc_manager_logs")
    log_dir.mkdir(exist_ok=True)
    
    # 配置日志格式
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    
    # 文件处理器
    log_file = log_dir / f"frpc_manager_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(log_format))
    file_handler.setLevel(logging.DEBUG)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))
    console_handler.setLevel(logging.INFO)
    
    # 配置根日志器
    logger = logging.getLogger('frpc_manager')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# 初始化日志
logger = setup_logging()

# ======================== 数据类 ========================
@dataclass
class FRPCConfig:
    """FRPC 配置数据类"""
    server_ip: str
    server_port: int
    token: str
    proxies: List[Dict[str, str]]
    extra_common: str = ""

@dataclass
class FRPCRuntimeInfo:
    """FRPC 运行时信息"""
    process: Optional[subprocess.Popen] = None
    restart_count: int = 0
    max_restarts: int = 3
    restart_delay: int = 5  # 重启延迟秒数
    stop_flag: bool = False
    log_buffer: List[str] = field(default_factory=list)
    last_error: str = ""

@dataclass
class ConfigVersion:
    """配置文件版本信息"""
    file_path: str
    version: str
    timestamp: datetime
    hash: str
    backup_path: str = ""

# ======================== 终端颜色类 ========================
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ======================== 工具函数 ========================
def clear_screen():
    """清屏函数"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def supports_color():
    """检查终端是否支持颜色"""
    return not platform.system() == 'Windows' or 'ANSICON' in os.environ

def calculate_file_hash(file_path: str) -> str:
    """计算文件的MD5哈希值"""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logger.error(f"计算文件哈希失败: {e}")
        return ""

def show_progress(block_num: int, block_size: int, total_size: int):
    """下载进度显示"""
    if total_size <= 0:
        return
    progress = min(block_num * block_size / total_size * 100, 100)
    print(f"\r下载进度: {progress:.1f}%", end='', flush=True)

def backup_config(file_path: str) -> str:
    """备份配置文件"""
    try:
        # 修复：使用Path对象处理路径
        backup_dir = Path("frpc_backups")
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        backup_file = backup_dir / f"{Path(file_path).name}.{timestamp}.bak"
        
        # 复制文件
        shutil.copy2(file_path, backup_file)
        
        # 记录版本信息
        version_info = ConfigVersion(
            file_path=file_path,
            version=timestamp,
            timestamp=datetime.now(),
            hash=calculate_file_hash(file_path),
            backup_path=str(backup_file)
        )
        
        # 保存版本信息 - 修复：datetime序列化问题
        version_file = Path(f"{file_path}.versions.json")
        versions = []
        if version_file.exists():
            with open(version_file, 'r', encoding='utf-8') as f:
                versions = json.load(f)
        
        versions.append({
            'file_path': version_info.file_path,
            'version': version_info.version,
            'timestamp': version_info.timestamp.isoformat(),  # 修复：使用ISO格式序列化时间
            'hash': version_info.hash,
            'backup_path': version_info.backup_path
        })
        
        with open(version_file, 'w', encoding='utf-8') as f:
            json.dump(versions, f, ensure_ascii=False, indent=2)
        
        logger.info(f"配置文件已备份: {backup_file}")
        return str(backup_file)
    except Exception as e:
        logger.error(f"备份配置文件失败: {e}")
        return ""

def rollback_config(file_path: str) -> bool:
    """回滚配置文件到上一个版本"""
    try:
        version_file = Path(f"{file_path}.versions.json")
        if not version_file.exists():
            logger.warning("没有版本记录，无法回滚")
            print(f"{bcolors.WARNING}没有版本记录，无法回滚{bcolors.ENDC}")
            return False
        
        with open(version_file, 'r', encoding='utf-8') as f:
            versions = json.load(f)
        
        if len(versions) < 1:
            logger.warning("没有备份版本，无法回滚")
            print(f"{bcolors.WARNING}没有备份版本，无法回滚{bcolors.ENDC}")
            return False
        
        # 获取最新备份
        latest_version = versions[-1]
        backup_path = latest_version['backup_path']
        
        if not Path(backup_path).exists():
            logger.error(f"备份文件不存在: {backup_path}")
            print(f"{bcolors.FAIL}备份文件不存在{bcolors.ENDC}")
            return False
        
        # 先备份当前版本
        backup_config(file_path)
        
        # 恢复备份
        shutil.copy2(backup_path, file_path)
        logger.info(f"配置文件已回滚到版本 {latest_version['version']}")
        print(f"{bcolors.OKGREEN}配置文件已回滚到版本 {latest_version['version']}{bcolors.ENDC}")
        
        return True
    except Exception as e:
        logger.error(f"回滚配置失败: {e}")
        print(f"{bcolors.FAIL}回滚失败: {e}{bcolors.ENDC}")
        return False

def check_file_permissions(file_path: str) -> bool:
    """检查配置文件权限是否安全"""
    try:
        file_path = Path(file_path)
        if platform.system() == 'Windows':
            # Windows权限检查（简化版）
            return True
        else:
            # Linux/macOS权限检查
            stat = file_path.stat()
            # 检查是否只有所有者可写
            if (stat.st_mode & 0o022) != 0:
                logger.warning(f"配置文件权限不安全: {file_path} (其他用户可写)")
                print(f"{bcolors.WARNING}警告: 配置文件 {file_path} 权限不安全，建议执行: chmod 600 {file_path}{bcolors.ENDC}")
                return False
            return True
    except Exception as e:
        logger.error(f"检查文件权限失败: {e}")
        return True

# ======================== 核心功能实现 ========================
def syntax_highlight_ini(content: str) -> str:
    """INI 语法高亮"""
    if not supports_color():
        return content
    
    lines = content.split('\n')
    highlighted = []
    
    for line in lines:
        line = SYNTAX_RULES['comment'].sub(f"{bcolors.WARNING}\\g<0>{bcolors.ENDC}", line)
        line = SYNTAX_RULES['section'].sub(f"{bcolors.HEADER}{bcolors.BOLD}\\g<0>{bcolors.ENDC}", line)
        line = SYNTAX_RULES['key'].sub(f"{bcolors.OKBLUE}\\g<1>{bcolors.ENDC} =", line)
        line = SYNTAX_RULES['string'].sub(f"{bcolors.OKGREEN}\\g<0>{bcolors.ENDC}", line)
        line = SYNTAX_RULES['number'].sub(f"{bcolors.OKCYAN}\\g<0>{bcolors.ENDC}", line)
        
        highlighted.append(line)
    
    return '\n'.join(highlighted)

def validate_field(value: str, rules: Dict) -> Tuple[bool, str]:
    """验证单个字段"""
    # 检查是否为空（必填字段）
    if rules.get('required', False) and not value:
        return False, f"字段不能为空: {rules.get('error', '必填字段')}"
    
    # 如果值为空且非必填，直接通过
    if not value and not rules.get('required', False):
        return True, ""
    
    # 正则表达式验证
    if 'pattern' in rules:
        pattern = re.compile(rules['pattern'])
        if not pattern.match(value):
            return False, rules['error']
    
    # 范围验证（数字）
    if 'range' in rules:
        try:
            num_value = int(value)
            min_val, max_val = rules['range']
            if not (min_val <= num_value <= max_val):
                return False, rules['error']
        except ValueError:
            return False, "值必须是数字"
    
    # 最小长度验证
    if 'min_length' in rules:
        if len(value) < rules['min_length']:
            return False, rules['error']
    
    return True, ""

def validate_frpc_config(content: str, file_type: str = '.ini') -> Tuple[bool, List[str]]:
    """增强的配置验证"""
    errors = []
    warnings = []
    logger.debug(f"开始验证配置，类型: {file_type}")
    
    try:
        if file_type == '.ini':
            lines = content.split('\n')
            has_common = False
            common_section = False
            proxy_sections = []
            
            for idx, line in enumerate(lines, 1):
                original_line = line
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # 检查段落
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1].strip()
                    if section == 'common':
                        has_common = True
                        common_section = True
                        continue
                    else:
                        common_section = False
                        proxy_sections.append(section)
                    continue
                
                # 检查键值对
                if '=' not in line:
                    errors.append(f"第{idx}行: 无效的配置格式，缺少 '=' -> {original_line}")
                    continue
                
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # 字段级验证
                if key in VALIDATION_RULES:
                    is_valid, error_msg = validate_field(value, VALIDATION_RULES[key])
                    if not is_valid:
                        errors.append(f"第{idx}行: {key} - {error_msg} -> {original_line}")
                
                # Common 部分验证
                if common_section:
                    if key == 'server_addr' and not value:
                        errors.append(f"第{idx}行: server_addr (服务器IP) 不能为空 -> {original_line}")
                    elif key == 'server_port':
                        try:
                            port = int(value)
                            if port < 1 or port > 65535:
                                warnings.append(f"第{idx}行: server_port {value} 超出有效端口范围(1-65535) -> {original_line}")
                        except ValueError:
                            errors.append(f"第{idx}行: server_port {value} 不是有效的数字 -> {original_line}")
            
            if not has_common:
                errors.append("缺少 [common] 核心配置段")
            
            if not proxy_sections:
                warnings.append("配置文件中未定义任何代理规则")
        
        elif file_type in ['.yml', '.yaml']:
            # YAML验证 + Schema检查
            data = yaml.safe_load(content)
            
            # 基础Schema验证
            if 'common' not in data:
                errors.append("缺少 common 配置节点")
            else:
                common = data['common']
                # 验证必填字段
                for field in ['server_addr', 'server_port']:
                    if field not in common:
                        errors.append(f"common 节点缺少 {field} 字段")
                    else:
                        if field in VALIDATION_RULES:
                            is_valid, error_msg = validate_field(str(common[field]), VALIDATION_RULES[field])
                            if not is_valid:
                                errors.append(f"common.{field}: {error_msg}")
        
        elif file_type == '.toml':
            data = tomllib.loads(content)
            # TOML验证逻辑
            if 'common' not in data:
                errors.append("缺少 common 配置节点")
            else:
                common = data['common']
                # 验证必填字段
                for field in ['server_addr', 'server_port']:
                    if field not in common:
                        errors.append(f"common 节点缺少 {field} 字段")
                    else:
                        if field in VALIDATION_RULES:
                            is_valid, error_msg = validate_field(str(common[field]), VALIDATION_RULES[field])
                            if not is_valid:
                                errors.append(f"common.{field}: {error_msg}")
        
        elif file_type == '.json':
            data = json.loads(content)
            # JSON验证逻辑
            if 'common' not in data:
                errors.append("缺少 common 配置节点")
            else:
                common = data['common']
                # 验证必填字段
                for field in ['server_addr', 'server_port']:
                    if field not in common:
                        errors.append(f"common 节点缺少 {field} 字段")
                    else:
                        if field in VALIDATION_RULES:
                            is_valid, error_msg = validate_field(str(common[field]), VALIDATION_RULES[field])
                            if not is_valid:
                                errors.append(f"common.{field}: {error_msg}")
        
    except yaml.YAMLError as e:
        errors.append(f"YAML 语法错误: {str(e)}")
        logger.error(f"YAML验证失败: {e}")
    except tomllib.TOMLDecodeError as e:
        errors.append(f"TOML 语法错误: {str(e)}")
        logger.error(f"TOML验证失败: {e}")
    except json.JSONDecodeError as e:
        errors.append(f"JSON 语法错误: {str(e)}")
        logger.error(f"JSON验证失败: {e}")
    except Exception as e:
        errors.append(f"配置验证失败: {str(e)}")
        logger.error(f"配置验证异常: {e}", exc_info=True)
    
    # 整理验证结果
    all_messages = []
    if errors:
        all_messages.extend([f"错误: {e}" for e in errors])
        logger.warning(f"配置验证发现 {len(errors)} 个错误")
    if warnings:
        all_messages.extend([f"警告: {w}" for w in warnings])
        logger.info(f"配置验证发现 {len(warnings)} 个警告")
    
    return len(errors) == 0, all_messages

def analyze_frpc_error(log_content: str) -> Dict:
    """分析 frpc 错误日志"""
    analysis_result = {
        'error_type': '未知错误',
        'description': '无法识别的错误类型',
        'solutions': ['查看日志详情排查问题'],
        'matched_text': '',
        'confidence': 0.0
    }
    
    if not log_content:
        return analysis_result
    
    # 遍历错误分析规则
    for rule in ERROR_ANALYSIS_RULES:
        pattern = re.compile(rule['pattern'], re.IGNORECASE)
        match = pattern.search(log_content)
        if match:
            analysis_result = {
                'error_type': rule['type'],
                'description': rule['description'],
                'solutions': rule['solutions'],
                'matched_text': match.group(0),
                'confidence': 1.0
            }
            logger.debug(f"识别到错误类型: {rule['type']}, 匹配文本: {match.group(0)}")
            break
    
    return analysis_result

async def async_monitor_frpc_log(process: subprocess.Popen, runtime_info: FRPCRuntimeInfo):
    """异步监控 frpc 日志"""
    logger.info("启动异步日志监控")
    print("\n=== frpc 运行日志 (按 Ctrl+C 停止) ===")
    print(f"{bcolors.WARNING}自动重启已启用，最大重启次数: {runtime_info.max_restarts}{bcolors.ENDC}")
    print("-" * 80)
    
    def read_output():
        error_buffer = []
        while not runtime_info.stop_flag and process.poll() is None:
            if process.stdout:
                try:
                    line = process.stdout.readline()
                    if line:
                        line_str = line.decode('utf-8', errors='ignore').strip()
                        runtime_info.log_buffer.append(line_str)
                        
                        # 收集错误信息
                        if any(keyword in line_str.lower() for keyword in ['error', 'failed', 'fatal']):
                            error_buffer.append(line_str)
                            runtime_info.last_error = line_str
                            logger.error(f"FRPC运行错误: {line_str}")
                        
                        # 日志级别高亮
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        if 'error' in line_str.lower():
                            print(f"{bcolors.FAIL}{timestamp} {line_str}{bcolors.ENDC}")
                        elif 'warning' in line_str.lower():
                            print(f"{bcolors.WARNING}{timestamp} {line_str}{bcolors.ENDC}")
                        elif 'success' in line_str.lower() or 'start' in line_str.lower():
                            print(f"{bcolors.OKGREEN}{timestamp} {line_str}{bcolors.ENDC}")
                        else:
                            print(f"{timestamp} {line_str}")
                            logger.debug(f"FRPC日志: {line_str}")
                except Exception as e:
                    logger.error(f"读取日志失败: {e}")
                    # 修复：添加退出条件，避免死循环
                    if runtime_info.stop_flag:
                        break
        
        # 保存最后的错误信息
        if error_buffer:
            runtime_info.last_error = '\n'.join(error_buffer[-5:])
    
    # 启动日志读取线程
    log_thread = threading.Thread(target=read_output, daemon=True)
    log_thread.start()
    
    # 异步等待进程结束
    while not runtime_info.stop_flag and process.poll() is None:
        await asyncio.sleep(1)
    
    # 修复：优雅停止日志线程
    runtime_info.stop_flag = True
    log_thread.join(timeout=5)
    logger.info("日志监控结束")

async def async_start_frpc(config_file: str, generate_script: bool = False):
    """异步启动 frpc (带自动重启)"""
    clear_screen()
    print(f"=== 启动 frpc - 配置: {config_file} ===")
    logger.info(f"启动FRPC，配置文件: {config_file}")
    
    # 检查配置文件权限
    check_file_permissions(config_file)
    
    # 初始化运行时信息
    runtime_info = FRPCRuntimeInfo(
        max_restarts=3,
        restart_delay=5
    )
    
    # 检查 frpc 是否存在
    frpc_exec = "frpc.exe" if platform.system() == "Windows" else "./frpc"
    if not Path(frpc_exec).exists():
        print(f"{bcolors.WARNING}未找到 frpc 可执行文件{bcolors.ENDC}")
        logger.warning("未找到FRPC可执行文件")
        
        download = input("是否自动下载？(y/n): ").strip().lower()
        if download == 'y':
            if await async_download_frpc():
                frpc_exec = "frpc.exe" if platform.system() == "Windows" else "./frpc"
            else:
                logger.error("FRPC下载失败")
                return
        else:
            custom_path = input("请输入 frpc 路径: ").strip()
            if Path(custom_path).exists():
                frpc_exec = custom_path
            else:
                print(f"{bcolors.FAIL}路径无效{bcolors.ENDC}")
                logger.error(f"FRPC路径无效: {custom_path}")
                return
    
    # 生成启动脚本
    if generate_script:
        script_ext = ".bat" if platform.system() == "Windows" else ".sh"
        script_name = f"start_frpc_{Path(config_file).stem}{script_ext}"
        
        try:
            async with aiofiles.open(script_name, 'w', encoding='utf-8') as f:
                if platform.system() == "Windows":
                    await f.write(f'@echo off\n"{frpc_exec}" -c "{config_file}"\npause')
                else:
                    await f.write(f'#!/bin/bash\nchmod +x {frpc_exec}\n./{frpc_exec} -c {config_file}')
            
            if platform.system() != "Windows":
                os.chmod(script_name, 0o755)
            
            print(f"{bcolors.OKGREEN}启动脚本已生成: {script_name}{bcolors.ENDC}")
            logger.info(f"生成启动脚本: {script_name}")
            
            # 修复：只生成脚本不启动frpc
            return
        except Exception as e:
            logger.error(f"生成启动脚本失败: {e}")
    
    # 主启动循环
    try:
        while not runtime_info.stop_flag and runtime_info.restart_count < runtime_info.max_restarts:
            try:
                cmd = [frpc_exec, "-c", config_file]
                print(f"\n{bcolors.OKBLUE}启动命令: {' '.join(cmd)}{bcolors.ENDC}")
                
                if runtime_info.restart_count > 0:
                    print(f"{bcolors.WARNING}自动重启 {runtime_info.restart_count}/{runtime_info.max_restarts} 次{bcolors.ENDC}")
                    logger.warning(f"FRPC异常退出，自动重启 {runtime_info.restart_count}/{runtime_info.max_restarts} 次")
                
                # 修复：跨平台兼容的subprocess参数
                creation_flags = 0
                if platform.system() == "Windows":
                    creation_flags = subprocess.CREATE_NO_WINDOW
                
                # 启动进程
                runtime_info.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=creation_flags
                )
                
                # 异步监控日志
                await async_monitor_frpc_log(runtime_info.process, runtime_info)
                
                # 检查退出状态
                exit_code = runtime_info.process.poll()
                if exit_code is not None and exit_code != 0 and not runtime_info.stop_flag:
                    runtime_info.restart_count += 1
                    logger.error(f"FRPC异常退出，退出码: {exit_code}")
                    
                    # 达到最大重启次数
                    if runtime_info.restart_count >= runtime_info.max_restarts:
                        print(f"\n{bcolors.FAIL}=== 达到最大重启次数，停止重启 ==={bcolors.ENDC}")
                        logger.error("达到最大重启次数，停止FRPC重启")
                        
                        # 错误分析
                        await async_analyze_and_report_errors(runtime_info, config_file)
                        break
                    
                    # 继续重启
                    print(f"\n{bcolors.WARNING}frpc 异常退出，{runtime_info.restart_delay} 秒后自动重启...{bcolors.ENDC}")
                    await asyncio.sleep(runtime_info.restart_delay)
                
            except Exception as e:
                logger.error(f"启动FRPC失败: {e}", exc_info=True)
                print(f"{bcolors.FAIL}启动失败: {e}{bcolors.ENDC}")
                runtime_info.restart_count += 1
                if runtime_info.restart_count < runtime_info.max_restarts:
                    await asyncio.sleep(runtime_info.restart_delay)
                else:
                    break
    except KeyboardInterrupt:
        # 修复：捕获Ctrl+C，优雅停止
        runtime_info.stop_flag = True
        if runtime_info.process and runtime_info.process.poll() is None:
            runtime_info.process.terminate()
            print(f"\n{bcolors.WARNING}用户中断，正在停止frpc...{bcolors.ENDC}")
    
    print(f"\n{bcolors.OKGREEN}frpc 进程已终止{bcolors.ENDC}")
    logger.info("FRPC进程已终止")

async def async_analyze_and_report_errors(runtime_info: FRPCRuntimeInfo, config_file: str):
    """异步分析错误并生成报告"""
    print(f"\n{bcolors.HEADER}=== 错误分析报告 ==={bcolors.ENDC}")
    
    # 分析错误
    log_content = '\n'.join(runtime_info.log_buffer)
    analysis = analyze_frpc_error(log_content or runtime_info.last_error)
    
    # 显示分析结果
    print(f"错误类型: {bcolors.FAIL}{analysis['error_type']}{bcolors.ENDC}")
    print(f"问题描述: {analysis['description']}")
    if analysis['matched_text']:
        print(f"关键错误: {bcolors.WARNING}{analysis['matched_text']}{bcolors.ENDC}")
    
    print(f"\n{bcolors.OKBLUE}解决方案:{bcolors.ENDC}")
    for i, solution in enumerate(analysis['solutions'], 1):
        print(f"  {i}. {solution}")
    
    # 异步保存日志
    log_file = f"frpc_error_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        async with aiofiles.open(log_file, 'w', encoding='utf-8') as f:
            await f.write(f"FRPC 错误日志 - {datetime.now()}\n")
            await f.write(f"配置文件: {config_file}\n")
            await f.write(f"重启次数: {runtime_info.restart_count}\n")
            await f.write(f"最后错误: {runtime_info.last_error}\n")
            await f.write("=" * 80 + "\n\n")
            await f.write(log_content)
        
        print(f"\n{bcolors.OKCYAN}完整日志已保存到: {log_file}{bcolors.ENDC}")
        logger.info(f"错误日志已保存: {log_file}")
    except Exception as e:
        logger.error(f"保存错误日志失败: {e}")

async def async_download_frpc(max_retries: int = 3, timeout: int = 30) -> bool:
    """异步下载FRPC（带重试和超时）"""
    clear_screen()
    print("=== 自动下载 frpc 客户端 ===")
    logger.info("开始下载FRPC客户端")
    
    # 检测系统
    system = platform.system().lower()
    arch = platform.machine().lower()
    
    # 映射系统架构
    download_mapping = {
        'windows': ('windows_amd64', 'frpc.exe', True),
        'linux': ('linux_amd64', 'frpc', False),
        'darwin': ('darwin_arm64' if arch in ['arm64', 'aarch64'] else 'darwin_amd64', 'frpc', False)
    }
    
    if system not in download_mapping:
        print(f"{bcolors.FAIL}不支持的系统: {system}{bcolors.ENDC}")
        logger.error(f"不支持的系统: {system}")
        return False
    
    download_key, frpc_file, is_zip = download_mapping[system]
    
    # 检查是否已存在
    if Path(frpc_file).exists():
        overwrite = input(f"\n{frpc_file} 已存在，是否覆盖？(y/n): ").strip().lower()
        if overwrite != 'y':
            return True
    
    # 下载文件（带重试）
    url = FRPC_DOWNLOAD_URLS[download_key]
    print(f"\n下载地址: {url}")
    logger.info(f"FRPC下载地址: {url}")
    
    temp_file = None
    try:
        for retry in range(max_retries):
            try:
                print("开始下载...")
                # 下载文件（带进度显示）
                temp_file, _ = urlretrieve(url, reporthook=show_progress, timeout=timeout)
                print()  # 换行
                
                # 解压
                if is_zip:
                    with zipfile.ZipFile(temp_file, 'r') as zipf:
                        # 查找 frpc 文件
                        for name in zipf.namelist():
                            if name.endswith(frpc_file):
                                zipf.extract(name)
                                shutil.move(name, frpc_file)
                                break
                else:
                    # 处理 tar.gz
                    with tarfile.open(temp_file, 'r:gz') as tarf:
                        for name in tarf.getnames():
                            if name.endswith(frpc_file):
                                tarf.extract(name)
                                shutil.move(name, frpc_file)
                                break
                
                # 设置可执行权限
                if system != 'windows':
                    Path(frpc_file).chmod(0o755)
                
                print(f"{bcolors.OKGREEN}下载完成！{frpc_file} 已保存到当前目录{bcolors.ENDC}")
                logger.info("FRPC下载完成")
                return True
                
            except URLError as e:
                logger.error(f"下载失败 (重试 {retry+1}/{max_retries}): {e}")
                if retry < max_retries - 1:
                    print(f"{bcolors.WARNING}下载失败，{5} 秒后重试...{bcolors.ENDC}")
                    await asyncio.sleep(5)
                else:
                    print(f"{bcolors.FAIL}下载失败: {e}{bcolors.ENDC}")
            except Exception as e:
                logger.error(f"下载/解压失败: {e}", exc_info=True)
                print(f"{bcolors.FAIL}下载失败: {e}{bcolors.ENDC}")
                return False
        return False
    finally:
        # 修复：清理临时文件
        if temp_file and Path(temp_file).exists():
            try:
                os.unlink(temp_file)
            except:
                pass

# ======================== 原有功能适配异步 ========================
def edit_config_file(file_path: str):
    """编辑配置文件（带备份）"""
    # 编辑前先备份
    backup_config(file_path)
    
    clear_screen()
    print(f"=== 编辑配置文件: {file_path} ===")
    print("说明: 输入内容，单独输入 'EOF' 结束编辑，输入 'CANCEL' 取消修改")
    print("-" * 60)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        # 语法高亮显示
        file_ext = Path(file_path).suffix.lower()
        if file_ext == '.ini':
            print(syntax_highlight_ini(original_content))
        else:
            print(original_content)
        
        print("-" * 60)
        print("请输入新的配置内容（逐行输入，单独输入 EOF 结束）:")
        
        # 接收新内容
        new_content = []
        while True:
            try:
                line = input()
                if line.strip().upper() == 'EOF':
                    break
                if line.strip().upper() == 'CANCEL':
                    print("取消修改")
                    logger.info("用户取消配置编辑")
                    return
                new_content.append(line)
            except EOFError:
                break
        
        new_content = '\n'.join(new_content)
        
        # 修复：空内容检查，避免清空配置文件
        if not new_content.strip():
            print(f"{bcolors.WARNING}配置内容为空，使用原有配置{bcolors.ENDC}")
            new_content = original_content
        
        # 验证配置
        print("\n=== 配置验证 ===")
        is_valid, messages = validate_frpc_config(new_content, file_ext)
        for msg in messages:
            if msg.startswith("错误"):
                print(f"{bcolors.FAIL}{msg}{bcolors.ENDC}")
            else:
                print(f"{bcolors.WARNING}{msg}{bcolors.ENDC}")
        
        if not is_valid:
            retry = input("\n配置存在错误，是否继续编辑？(y/n): ").strip().lower()
            if retry == 'y':
                edit_config_file(file_path)
            return
        
        # 保存配置
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"{bcolors.OKGREEN}配置文件已保存！{bcolors.ENDC}")
        logger.info(f"配置文件已更新: {file_path}")
        
    except Exception as e:
        logger.error(f"编辑配置失败: {e}", exc_info=True)
        print(f"{bcolors.FAIL}编辑配置失败: {e}{bcolors.ENDC}")

def find_frpc_configs() -> Dict[str, str]:
    """查找配置文件"""
    config_files = {}
    for file in os.listdir('.'):
        file_ext = Path(file).suffix.lower()
        if file_ext in SUPPORTED_CONFIG_TYPES:
            config_files[file] = file_ext
    return config_files

def parse_frpc_config(file_path: str, file_type: str) -> Optional[Dict]:
    """解析配置文件"""
    try:
        if file_type == '.ini':
            config = {}
            with open(file_path, 'r', encoding='utf-8') as f:
                in_common = False
                current_section = None
                for line in f:
                    line = line.strip()
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1].strip()
                        config[current_section] = {}
                        if current_section == 'common':
                            in_common = True
                        else:
                            in_common = False
                        continue
                    if in_common and '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        config['common'][key.strip()] = value.strip()
            return config
        
        elif file_type in ['.yml', '.yaml']:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        
        elif file_type == '.toml':
            with open(file_path, 'rb') as f:
                return tomllib.load(f)
        
        elif file_type == '.json':
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"解析配置文件失败: {e}", exc_info=True)
        print(f"{bcolors.FAIL}解析配置文件失败: {e}{bcolors.ENDC}")
        return None

def show_config_info(config_data: Dict, file_name: str):
    """展示配置信息（Token部分隐藏）"""
    print(f"\n=== 配置文件 {file_name} 关键信息 ===")
    common = config_data.get('common', config_data)
    server_ip = common.get('server_addr', common.get('server_ip', '未知'))
    server_port = common.get('server_port', '未知')
    token = common.get('token', '未设置')
    
    print(f"服务器 IP: {bcolors.OKCYAN}{server_ip}{bcolors.ENDC}")
    print(f"服务器端口: {bcolors.OKCYAN}{server_port}{bcolors.ENDC}")
    
    # Token部分隐藏
    if token and token != '未设置':
        # 显示前8位，后面用*代替
        hidden_token = token[:8] + '*' * max(0, len(token) - 8)
        print(f"认证 Token: {bcolors.WARNING}{hidden_token}{bcolors.ENDC}")
    else:
        print("认证 Token: 未设置")
    
    proxy_count = 0
    proxies = []
    for key, value in config_data.items():
        if key != 'common' and isinstance(value, dict):
            proxy_count += 1
            proxies.append({
                'name': key,
                'type': value.get('type', '未知'),
                'local_port': value.get('local_port', '未知'),
                'remote_port': value.get('remote_port', '未知')
            })
    
    print(f"代理配置数量: {bcolors.OKGREEN}{proxy_count}{bcolors.ENDC}")
    
    if proxies:
        print("\n代理详情:")
        for p in proxies:
            print(f"  - {p['name']} ({p['type']}): 本地{p['local_port']} → 远程{p['remote_port']}")
    
    print("=" * 60)

def generate_from_template() -> str:
    """从模板生成配置"""
    clear_screen()
    print("=== 从模板生成配置 ===")
    print("可用模板:")
    for idx, (name, _) in enumerate(CONFIG_TEMPLATES.items(), 1):
        print(f"  {idx}. {name}")
    
    try:
        sel = int(input("\n选择模板 (1-{}): ".format(len(CONFIG_TEMPLATES))).strip())
        if not 1 <= sel <= len(CONFIG_TEMPLATES):
            print(f"{bcolors.WARNING}无效选择{bcolors.ENDC}")
            return ""
        
        template_name = list(CONFIG_TEMPLATES.keys())[sel-1]
        template = CONFIG_TEMPLATES[template_name]
        
        # 收集参数
        params = {}
        params['server_ip'] = input("服务器 IP 地址: ").strip()
        params['server_port'] = input("服务器端口 (默认7000): ").strip() or "7000"
        params['token'] = input("认证 Token: ").strip()
        
        if 'remote_port' in template:
            params['remote_port'] = input("远程端口: ").strip()
        if 'local_port' in template:
            params['local_port'] = input("本地端口: ").strip()
        if 'domain' in template:
            params['domain'] = input("自定义域名: ").strip()
        
        # 生成配置
        config_content = template.format(**params)
        logger.info(f"从模板 {template_name} 生成配置")
        return config_content
    
    except ValueError:
        logger.error("模板选择输入无效")
        print(f"{bcolors.FAIL}输入无效{bcolors.ENDC}")
        return ""
    except KeyError as e:
        logger.error(f"模板参数缺失: {e}")
        print(f"{bcolors.FAIL}缺少参数: {e}{bcolors.ENDC}")
        return ""

def generate_frpc_config() -> str:
    """生成配置"""
    clear_screen()
    print("=== 自动生成 frpc 配置文件 ===")
    print("1. 手动填写配置")
    print("2. 使用模板生成")
    
    choice = input("\n选择方式 (1/2): ").strip()
    if choice == '2':
        content = generate_from_template()
        if not content:
            return ""
    else:
        # 手动生成
        server_ip = input("服务器 IP 地址: ").strip()
        while not server_ip:
            print(f"{bcolors.FAIL}IP 不能为空{bcolors.ENDC}")
            server_ip = input("服务器 IP 地址: ").strip()
        
        server_port = input("服务器端口 (默认7000): ").strip() or "7000"
        token = input("认证 Token: ").strip()
        extra_common = input("额外 common 配置 (每行一个):\n")
        extra_common = '\n'.join([l.strip() for l in extra_common.split('\n') if l.strip()])
        
        # 代理配置
        proxies = []
        print("\n=== 添加代理 ===")
        while True:
            proxy_name = input("代理名称 (留空结束): ").strip()
            if not proxy_name:
                break
            
            proxy_type = input(f"{proxy_name} 类型 (tcp/udp/http/https): ").strip() or "tcp"
            local_ip = input(f"{proxy_name} 本地IP (默认127.0.0.1): ").strip() or "127.0.0.1"
            local_port = input(f"{proxy_name} 本地端口: ").strip()
            while not local_port:
                print(f"{bcolors.FAIL}端口不能为空{bcolors.ENDC}")
                local_port = input(f"{proxy_name} 本地端口: ").strip()
            
            remote_port = input(f"{proxy_name} 远程端口: ").strip()
            while not remote_port:
                print(f"{bcolors.FAIL}端口不能为空{bcolors.ENDC}")
                remote_port = input(f"{proxy_name} 远程端口: ").strip()
            
            proxies.append({
                'name': proxy_name, 'type': proxy_type,
                'local_ip': local_ip, 'local_port': local_port,
                'remote_port': remote_port
            })
        
        # 生成配置
        proxies_config = ""
        for p in proxies:
            proxies_config += f"\n[{p['name']}]\ntype = {p['type']}\nlocal_ip = {p['local_ip']}\nlocal_port = {p['local_port']}\nremote_port = {p['remote_port']}\n"
        
        content = f"""[common]
server_addr = {server_ip}
server_port = {server_port}
token = {token}
{extra_common}

{proxies_config}"""
    
    # 验证配置
    print("\n=== 配置验证 ===")
    is_valid, messages = validate_frpc_config(content)
    for msg in messages:
        if msg.startswith("错误"):
            print(f"{bcolors.FAIL}{msg}{bcolors.ENDC}")
        else:
            print(f"{bcolors.WARNING}{msg}{bcolors.ENDC}")
    
    if not is_valid:
        retry = input("\n配置有错误，是否编辑？(y/n): ").strip().lower()
        if retry == 'y':
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
                f.write(content)
                temp_file = f.name
            
            edit_config_file(temp_file)
            
            with open(temp_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            os.unlink(temp_file)
    
    return content

def paste_frpc_config() -> str:
    """粘贴配置"""
    clear_screen()
    print("=== 粘贴 frpc 配置内容 ===")
    print("粘贴配置内容 (输入 EOF 结束):")
    print("-" * 60)
    
    config_lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == "EOF":
                break
            config_lines.append(line)
        except EOFError:
            break
    
    content = '\n'.join(config_lines)
    if not content.strip():
        print(f"{bcolors.FAIL}配置为空{bcolors.ENDC}")
        return ""
    
    # 验证配置
    print("\n=== 配置验证 ===")
    is_valid, messages = validate_frpc_config(content)
    for msg in messages:
        if msg.startswith("错误"):
            print(f"{bcolors.FAIL}{msg}{bcolors.ENDC}")
        else:
            print(f"{bcolors.WARNING}{msg}{bcolors.ENDC}")
    
    return content

def batch_operation():
    """批量操作"""
    clear_screen()
    print("=== 批量操作 ===")
    config_files = find_frpc_configs()
    if not config_files:
        print(f"{bcolors.WARNING}未找到配置文件{bcolors.ENDC}")
        return
    
    print("找到的配置文件:")
    for idx, file in enumerate(config_files.keys(), 1):
        print(f"  {idx}. {file}")
    
    print("\n批量操作:")
    print("1. 批量验证配置")
    print("2. 批量生成启动脚本")
    print("3. 导出所有配置信息")
    print("4. 批量备份配置")
    print("5. 配置版本管理")
    
    choice = input("\n选择操作 (1-5): ").strip()
    
    if choice == '1':
        print("\n=== 批量验证结果 ===")
        for file, ext in config_files.items():
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            is_valid, messages = validate_frpc_config(content, ext)
            print(f"\n{file}: {'✅ 有效' if is_valid else '❌ 无效'}")
            for msg in messages:
                print(f"  - {msg}")
    
    elif choice == '2':
        # 修复：批量生成脚本时不启动frpc
        print("\n=== 批量生成启动脚本 ===")
        for file in config_files.keys():
            script_ext = ".bat" if platform.system() == "Windows" else ".sh"
            script_name = f"start_frpc_{Path(file).stem}{script_ext}"
            
            try:
                frpc_exec = "frpc.exe" if platform.system() == "Windows" else "./frpc"
                with open(script_name, 'w', encoding='utf-8') as f:
                    if platform.system() == "Windows":
                        f.write(f'@echo off\n"{frpc_exec}" -c "{file}"\npause')
                    else:
                        f.write(f'#!/bin/bash\nchmod +x {frpc_exec}\n./{frpc_exec} -c {file}')
                
                if platform.system() != "Windows":
                    os.chmod(script_name, 0o755)
                
                print(f"  ✅ {file} -> {script_name}")
                logger.info(f"生成启动脚本: {script_name}")
            except Exception as e:
                print(f"  ❌ {file}: {e}")
                logger.error(f"生成启动脚本失败 {file}: {e}")
    
    elif choice == '3':
        export_file = f"frpc_configs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(export_file, 'w', encoding='utf-8') as f:
            f.write(f"# FRPC 配置导出 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for file, ext in config_files.items():
                f.write(f"## {file}\n\n")
                config_data = parse_frpc_config(file, ext)
                if config_data:
                    common = config_data.get('common', {})
                    server_ip = common.get('server_addr', '未知')
                    server_port = common.get('server_port', '未知')
                    # Token导出时也隐藏
                    token = common.get('token', '未设置')
                    hidden_token = token[:8] + '****' if token and token != '未设置' else '未设置'
                    
                    f.write(f"- 服务器IP: {server_ip}\n")
                    f.write(f"- 服务器端口: {server_port}\n")
                    f.write(f"- Token: {hidden_token}\n\n")
        
        print(f"{bcolors.OKGREEN}配置信息已导出到: {export_file}{bcolors.ENDC}")
    
    elif choice == '4':
        print("\n=== 批量备份配置 ===")
        for file in config_files.keys():
            backup_path = backup_config(file)
            if backup_path:
                print(f"  ✅ {file} -> {backup_path}")
            else:
                print(f"  ❌ {file} 备份失败")
    
    elif choice == '5':
        print("\n=== 配置版本管理 ===")
        for file in config_files.keys():
            print(f"\n{file}:")
            version_file = f"{file}.versions.json"
            if Path(version_file).exists():
                with open(version_file, 'r', encoding='utf-8') as f:
                    versions = json.load(f)
                
                print(f"  版本数量: {len(versions)}")
                for i, ver in enumerate(versions[-5:], 1):  # 只显示最近5个版本
                    print(f"  {i}. 版本: {ver['version']} - {ver['timestamp']}")
                
                if input(f"\n是否回滚 {file} 到上一版本？(y/n): ").strip().lower() == 'y':
                    rollback_config(file)
            else:
                print("  无版本记录")

# ======================== 主函数 ========================
def main():
    """主程序"""
    clear_screen()
    print(f"{bcolors.HEADER}{bcolors.BOLD}===== frpc 全能管理工具 v4.0 (企业级) ====={bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}特性: 增强验证 | 安全加固 | 结构化日志 | 版本管理 | 异步处理{bcolors.ENDC}")
    
    while True:
        print("\n请选择操作:")
        print("1. 管理现有配置文件")
        print("2. 生成新配置文件")
        print("3. 编辑配置文件")
        print("4. 批量操作")
        print("5. 下载/更新 frpc 客户端")
        print("6. 配置版本管理")
        print("7. 退出")
        
        choice = input("\n输入选项 (1-7): ").strip()
        
        if choice == '1':
            config_files = find_frpc_configs()
            if not config_files:
                print(f"{bcolors.WARNING}未找到配置文件{bcolors.ENDC}")
                continue
            
            print(f"\n找到 {len(config_files)} 个配置文件:")
            for idx, (file, ext) in enumerate(config_files.items(), 1):
                print(f"  {idx}. {file} ({ext[1:]})")
            
            sel = input("\n选择文件 (输入序号，或 'all' 查看全部信息): ").strip()
            if sel.lower() == 'all':
                for file, ext in config_files.items():
                    data = parse_frpc_config(file, ext)
                    if data:
                        show_config_info(data, file)
            else:
                try:
                    idx = int(sel) - 1
                    file_name = list(config_files.keys())[idx]
                    file_ext = config_files[file_name]
                    
                    print(f"\n=== 操作 {file_name} ===")
                    print("1. 查看信息")
                    print("2. 验证配置")
                    print("3. 启动 frpc (带自动重启)")
                    print("4. 生成启动脚本")
                    print("5. 备份配置")
                    print("6. 回滚配置")
                    print("7. 返回")
                    
                    sub_choice = input("\n选择操作 (1-7): ").strip()
                    if sub_choice == '1':
                        data = parse_frpc_config(file_name, file_ext)
                        if data:
                            show_config_info(data, file_name)
                    elif sub_choice == '2':
                        with open(file_name, 'r', encoding='utf-8') as f:
                            content = f.read()
                        is_valid, messages = validate_frpc_config(content, file_ext)
                        print(f"\n验证结果: {'✅ 有效' if is_valid else '❌ 无效'}")
                        for msg in messages:
                            print(f"  - {msg}")
                    elif sub_choice == '3':
                        asyncio.run(async_start_frpc(file_name))
                    elif sub_choice == '4':
                        asyncio.run(async_start_frpc(file_name, generate_script=True))
                    elif sub_choice == '5':
                        backup_path = backup_config(file_name)
                        if backup_path:
                            print(f"{bcolors.OKGREEN}配置已备份到: {backup_path}{bcolors.ENDC}")
                    elif sub_choice == '6':
                        rollback_config(file_name)
                    
                except (ValueError, IndexError):
                    print(f"{bcolors.FAIL}无效选择{bcolors.ENDC}")
        
        elif choice == '2':
            print("\n生成方式:")
            print("1. 自动生成")
            print("2. 粘贴配置")
            print("3. 从模板生成")
            
            gen_choice = input("\n选择 (1-3): ").strip()
            if gen_choice == '1':
                content = generate_frpc_config()
            elif gen_choice == '2':
                content = paste_frpc_config()
            elif gen_choice == '3':
                content = generate_from_template()
            else:
                print(f"{bcolors.WARNING}无效选择{bcolors.ENDC}")
                continue
            
            if content:
                file_name = input("\n保存为 (默认 frpc_auto.ini): ").strip() or "frpc_auto.ini"
                if not Path(file_name).suffix:
                    file_name += ".ini"
                
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"{bcolors.OKGREEN}配置已保存到: {file_name}{bcolors.ENDC}")
                logger.info(f"新配置已保存: {file_name}")
                
                if input("是否立即启动？(y/n): ").strip().lower() == 'y':
                    asyncio.run(async_start_frpc(file_name))
        
        elif choice == '3':
            config_files = find_frpc_configs()
            if not config_files:
                print(f"{bcolors.WARNING}未找到配置文件{bcolors.ENDC}")
                if input("是否创建新配置？(y/n): ").strip().lower() == 'y':
                    file_name = input("新配置文件名: ").strip() or "frpc_new.ini"
                    if not Path(file_name).suffix:
                        file_name += ".ini"
                    with open(file_name, 'w', encoding='utf-8') as f:
                        f.write("[common]\nserver_addr =\nserver_port = 7000\ntoken =\n")
                    edit_config_file(file_name)
                continue
            
            print("\n选择要编辑的文件:")
            for idx, file in enumerate(config_files.keys(), 1):
                print(f"  {idx}. {file}")
            
            try:
                sel = int(input("\n输入序号: ").strip()) - 1
                file_name = list(config_files.keys())[sel]
                edit_config_file(file_name)
            except (ValueError, IndexError):
                print(f"{bcolors.FAIL}无效选择{bcolors.ENDC}")
        
        elif choice == '4':
            batch_operation()
        
        elif choice == '5':
            asyncio.run(async_download_frpc())
        
        elif choice == '6':
            print("\n=== 配置版本管理 ===")
            config_files = find_frpc_configs()
            if not config_files:
                print(f"{bcolors.WARNING}未找到配置文件{bcolors.ENDC}")
                continue
            
            for file in config_files.keys():
                print(f"\n📄 {file}")
                version_file = Path(f"{file}.versions.json")
                
                if version_file.exists():
                    with open(version_file, 'r', encoding='utf-8') as f:
                        versions = json.load(f)
                    
                    print(f"  🔢 版本数量: {len(versions)}")
                    if versions:
                        print("  📜 版本记录 (最近5个):")
                        for i, ver in enumerate(versions[-5:], 1):
                            print(f"    {i}. {ver['version']} - {ver['timestamp']}")
                        
                        action = input("  操作 (B=备份/R=回滚/N=下一个文件): ").strip().upper()
                        if action == 'B':
                            backup_config(file)
                        elif action == 'R':
                            rollback_config(file)
                else:
                    print("  🚫 无版本记录")
                    if input("  是否创建备份？(y/n): ").strip().lower() == 'y':
                        backup_config(file)
        
        elif choice == '7':
            logger.info("用户退出程序")
            print("退出程序")
            sys.exit(0)
        
        else:
            print(f"{bcolors.FAIL}无效选项{bcolors.ENDC}")
        
        input("\n按回车键继续...")
        clear_screen()

# ======================== 单元测试示例 ========================
def test_validation_rules():
    """测试验证规则"""
    logger.info("运行验证规则测试")
    
    # 测试IP验证
    test_cases = [
        ('server_addr', '192.168.1.1', True),
        ('server_addr', 'example.com', True),
        ('server_addr', '256.1.1.1', False),
        ('server_port', '7000', True),
        ('server_port', '0', False),
        ('server_port', '65536', False),
    ]
    
    for field, value, expected in test_cases:
        is_valid, error = validate_field(value, VALIDATION_RULES[field])
        assert is_valid == expected, f"测试失败: {field}={value}, 期望{expected}, 实际{is_valid}, 错误:{error}"
        print(f"✅ 测试 {field}={value}: {'通过' if is_valid == expected else '失败'}")

# ======================== 程序入口 ========================
if __name__ == "__main__":
    # 运行单元测试（可选）
    # test_validation_rules()
    
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断程序")
        print(f"\n{bcolors.WARNING}\n程序已退出{bcolors.ENDC}")
    except Exception as e:
        logger.error(f"程序异常退出: {e}", exc_info=True)
        print(f"\n{bcolors.FAIL}程序出错: {e}{bcolors.ENDC}")
        traceback.print_exc()
        sys.exit(1)