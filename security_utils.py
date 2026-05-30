"""
安全工具模块

提供XSS防护、输入校验、数据清理等安全功能
"""

import html
import re


def safe_html(text: str) -> str:
    """
    对文本进行HTML转义，防止XSS攻击
    
    Args:
        text: 原始文本（可能包含AI生成的内容）
    
    Returns:
        HTML转义后的安全文本
    """
    if not text:
        return ""
    return html.escape(text)


def sanitize_input(text: str, max_length: int = 128) -> str:
    """
    清理用户输入，防止注入攻击
    
    Args:
        text: 用户输入文本
        max_length: 最大允许长度
    
    Returns:
        清理后的文本
    """
    if not text:
        return ""
    
    # 截断超长输入
    text = text[:max_length]
    
    # 移除控制字符（保留换行和制表符）
    text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
    
    return text


def validate_password_input(password: str) -> tuple[bool, str]:
    """
    验证密码输入的合法性
    
    Args:
        password: 用户输入的密码
    
    Returns:
        (是否有效, 错误信息)
    """
    if not password:
        return False, "请输入密码"
    
    if len(password) > 128:
        return False, "密码长度不能超过128字符"
    
    # 检查是否包含明显的注入尝试
    dangerous_patterns = [
        r'<script',           # XSS
        r'javascript:',       # JS伪协议
        r'on\w+\s*=',         # 事件处理器
        r'\$\{.*\}',          # 模板注入
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return False, "输入包含不安全内容，请重新输入"
    
    return True, ""


def clear_sensitive_session_state():
    """
    清除session state中可能包含敏感数据的键
    用于Streamlit环境
    """
    import streamlit as st
    
    sensitive_keys = [
        'password', 'pwd', 'eval_password', 
        'generated_password', 'temp_pwd'
    ]
    
    for key in list(st.session_state.keys()):
        if any(sk in key.lower() for sk in sensitive_keys):
            # 覆盖后再删除（最佳努力）
            st.session_state[key] = "0" * 128
            del st.session_state[key]