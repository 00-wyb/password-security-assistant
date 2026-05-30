"""
密码强度评估规则引擎
实现多维度评分算法
"""

import re
import math
from typing import Dict, List, Tuple


def calculate_entropy(password: str) -> float:
    """
    计算 Shannon 熵值
    
    公式: H = -Σ p(x) * log2(p(x))，再乘以长度
    """
    if not password:
        return 0.0
    
    # 统计字符频率
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # 计算熵
    entropy = 0.0
    length = len(password)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    # 总熵 = 每字符熵 × 长度
    return entropy * length


def check_common_patterns(password: str) -> Tuple[int, List[str]]:
    """
    检测常见弱密码模式
    
    Returns:
        (扣分, 检测到的模式列表)
    """
    pwd_lower = password.lower()
    patterns_found = []
    penalty = 0
    
    # 常见弱密码字典
    common_passwords = [
        'password', '123456', 'qwerty', 'admin', 'letmein',
        'welcome', 'monkey', 'dragon', 'master', 'hello123',
        'iloveyou', 'princess', 'abc123', 'football', 'baseball'
    ]
    
    # 键盘路径
    keyboard_patterns = [
        'qwerty', 'asdf', 'zxcv', 'qazwsx', '1qaz2wsx',
        '1234567890', '0987654321', 'abcdefg'
    ]
    
    # 重复字符
    if len(set(password)) == 1:
        patterns_found.append("完全重复字符")
        penalty += 30
    
    # 连续相同字符（3个以上）
    if re.search(r'(.)\1{2,}', password):
        patterns_found.append("连续重复字符")
        penalty += 15
    
    # 常见弱密码
    for common in common_passwords:
        if common in pwd_lower or pwd_lower in common:
            patterns_found.append(f"常见弱密码模式: {common}")
            penalty += 25
            break
    
    # 键盘路径
    for pattern in keyboard_patterns:
        if pattern in pwd_lower:
            patterns_found.append(f"键盘路径: {pattern}")
            penalty += 20
            break
    
    # 简单序列
    if re.search(r'012|123|234|345|456|567|678|789|890', password):
        patterns_found.append("数字序列")
        penalty += 10
    
    # 日期模式
    if re.search(r'(19|20)\d{2}', password):  # 1900-2099
        patterns_found.append("年份模式")
        penalty += 5
    
    return penalty, patterns_found


def evaluate_password(password: str) -> Dict:
    """
    综合密码强度评估
    
    Returns:
        {
            'score': 综合评分(0-100),
            'level': 等级标签,
            'length_score': 长度评分,
            'complexity_score': 复杂度评分,
            'pattern_score': 模式评分,
            'entropy_score': 熵值评分,
            'entropy': 原始熵值,
            'length': 密码长度,
            'char_types': 字符种类数,
            'patterns_found': 检测到的模式列表,
            'suggestions': 改进建议列表
        }
    """
    if not password:
        return {
            'score': 0,
            'level': '无输入',
            'length_score': 0,
            'complexity_score': 0,
            'pattern_score': 0,
            'entropy_score': 0,
            'entropy': 0,
            'length': 0,
            'char_types': 0,
            'patterns_found': [],
            'suggestions': ['请输入密码']
        }
    
    length = len(password)
    
    # ========== 1. 长度评分 (0-40分) ==========
    length_score = 0
    if length >= 8:
        length_score = 5
    if length >= 12:
        length_score = 15
    if length >= 16:
        length_score = 25
    if length >= 20:
        length_score = 35
    if length >= 24:
        length_score = 40
    
    # ========== 2. 复杂度评分 (0-30分) ==========
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    char_types = sum([has_lower, has_upper, has_digit, has_symbol])
    
    complexity_score = char_types * 7  # 1种=7, 2种=14, 3种=21, 4种=28
    if complexity_score > 30:
        complexity_score = 30
    
    # ========== 3. 模式检测评分 (0-30分) ==========
    pattern_penalty, patterns_found = check_common_patterns(password)
    pattern_score = max(0, 30 - pattern_penalty)
    
    # ========== 4. 熵值评分 (0-25分) ==========
    entropy = calculate_entropy(password)
    
    entropy_score = 0
    if entropy >= 28:
        entropy_score = 5
    if entropy >= 35:
        entropy_score = 10
    if entropy >= 45:
        entropy_score = 17
    if entropy >= 60:
        entropy_score = 25
    
    # ========== 综合评分 ==========
    total_score = length_score + complexity_score + pattern_score + entropy_score
    total_score = max(0, min(100, total_score))
    
    # ========== 等级划分 ==========
    if total_score >= 90:
        level = '极强'
        color = '#059669'  # 深绿
    elif total_score >= 70:
        level = '强'
        color = '#10b981'  # 绿
    elif total_score >= 40:
        level = '中等'
        color = '#f59e0b'  # 橙
    elif total_score >= 20:
        level = '弱'
        color = '#ef4444'  # 红
    else:
        level = '极弱'
        color = '#dc2626'  # 深红
    
    # ========== 生成改进建议 ==========
    suggestions = []
    
    if length < 12:
        suggestions.append('增加密码长度至12位以上（推荐16位）')
    elif length < 16:
        suggestions.append('可考虑增加长度至16位以提升安全性')
    
    if char_types < 3:
        suggestions.append('混合使用大小写字母、数字和符号')
    elif char_types < 4:
        suggestions.append('可添加特殊符号进一步提升复杂度')
    
    if patterns_found:
        suggestions.append('避免使用常见单词、键盘路径、重复序列等可预测模式')
    
    if entropy < 45:
        suggestions.append('增加随机性，避免规律性字符排列')
    
    if not suggestions:
        suggestions.append('密码强度良好，建议启用双因素认证（2FA）')
    
    return {
        'score': total_score,
        'level': level,
        'color': color,
        'length_score': length_score,
        'complexity_score': complexity_score,
        'pattern_score': pattern_score,
        'entropy_score': entropy_score,
        'entropy': round(entropy, 1),
        'length': length,
        'char_types': char_types,
        'has_lower': has_lower,
        'has_upper': has_upper,
        'has_digit': has_digit,
        'has_symbol': has_symbol,
        'patterns_found': patterns_found,
        'suggestions': suggestions
    }


# 测试代码
if __name__ == "__main__":
    test_passwords = [
        "123456",                    # 极弱
        "password",                  # 极弱
        "HelloWorld1",              # 弱
        "MyP@ssw0rd2024!",          # 强
        "Tr0ub4dor&3",              # 中等
        "this-is-my-very-long-random-password-2026!",  # 极强
    ]
    
    for pwd in test_passwords:
        result = evaluate_password(pwd)
        masked = pwd[:3] + "*" * (len(pwd) - 3)
        print(f"\n密码: {masked}")
        print(f"  评分: {result['score']}/100 ({result['level']})")
        print(f"  熵值: {result['entropy']} bits")
        print(f"  长度: {result['length']}, 字符种类: {result['char_types']}/4")
        if result['patterns_found']:
            print(f"  风险模式: {', '.join(result['patterns_found'])}")
        print(f"  建议: {'; '.join(result['suggestions'][:2])}")