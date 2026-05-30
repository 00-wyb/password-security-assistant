"""
Have I Been Pwned API 客户端
实现 k-匿名协议查询密码泄露状态
无需 API 密钥
"""

import hashlib
import requests
from typing import Tuple


def sha1_hash(password: str) -> str:
    """
    计算密码的 SHA-1 哈希值（大写）
    
    Args:
        password: 原始密码明文
    
    Returns:
        40位十六进制大写字符串
    """
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()


def check_pwned(password: str) -> Tuple[bool, int]:
    """
    查询密码是否在泄露数据库中（k-匿名协议）
    
    无需 API 密钥，直接调用 HIBP Pwned Passwords API
    
    Args:
        password: 原始密码明文
    
    Returns:
        (是否泄露, 泄露次数)
        - (True, n): 已泄露 n 次
        - (False, 0): 未泄露
        - (False, -1): 查询失败（API故障或网络问题）
    """
    # 1. 计算 SHA-1 哈希
    full_hash = sha1_hash(password)
    
    # 2. 提取前缀（前5位）和后缀（后35位）
    prefix = full_hash[:5]
    suffix = full_hash[5:]
    
    # 3. 调用 HIBP Pwned Passwords API（无需认证）
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={
                "Add-Padding": "true",  # 防止时序攻击
                "User-Agent": "PasswordSecurityAssistant/1.0"
            },
            timeout=10
        )
        
        # 检查响应状态
        if response.status_code != 200:
            print(f"HIBP API 错误: {response.status_code}")
            return False, -1
        
        # 4. 解析响应，本地匹配后缀
        # 响应格式：每行 "HASH_SUFFIX:COUNT"
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            
            hash_suffix, count_str = line.split(":", 1)
            
            # 匹配成功！
            if hash_suffix == suffix:
                return True, int(count_str)
        
        # 未找到匹配
        return False, 0
        
    except requests.exceptions.Timeout:
        print("HIBP API 请求超时")
        return False, -1
    except requests.exceptions.RequestException as e:
        print(f"HIBP API 请求失败: {e}")
        return False, -1


# 测试代码
if __name__ == "__main__":
    # 测试用例
    test_passwords = [
        "password",      # 常见弱密码，应已泄露
        "123456",        # 常见弱密码，应已泄露
        "this-is-a-very-long-random-password-2026",  # 强密码，应未泄露
    ]
    
    for pwd in test_passwords:
        is_pwned, count = check_pwned(pwd)
        
        if count == -1:
            status = "查询失败"
        elif is_pwned:
            status = f"已泄露 {count:,} 次"
        else:
            status = "未泄露"
        
        # 只显示前3位，保护隐私
        masked = pwd[:3] + "*" * (len(pwd) - 3)
        print(f"密码 '{masked}': {status}")