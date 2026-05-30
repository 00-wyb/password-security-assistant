"""
密码生成器模块

实现密码学安全的密码生成
核心原则：使用 secrets 模块（CSPRNG），绝不使用 random
"""

import secrets
import string
from typing import List, Tuple


def generate_random_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digit: bool = True,
    use_symbol: bool = True,
    exclude_ambiguous: bool = True
) -> Tuple[str, float]:
    """
    生成密码学安全的随机密码
    
    Args:
        length: 密码长度（8-32）
        use_upper: 包含大写字母
        use_lower: 包含小写字母
        use_digit: 包含数字
        use_symbol: 包含符号
        exclude_ambiguous: 排除易混淆字符（0/O/1/l/I）
    
    Returns:
        (生成的密码, 熵值估算)
    """
    # 构建字符池
    char_pool = ""
    required_chars = []
    
    if use_lower:
        lower_chars = string.ascii_lowercase
        if exclude_ambiguous:
            lower_chars = lower_chars.replace('l', '')
        char_pool += lower_chars
        required_chars.append(secrets.choice(lower_chars))
    
    if use_upper:
        upper_chars = string.ascii_uppercase
        if exclude_ambiguous:
            upper_chars = upper_chars.replace('O', '')
        char_pool += upper_chars
        required_chars.append(secrets.choice(upper_chars))
    
    if use_digit:
        digit_chars = string.digits
        if exclude_ambiguous:
            digit_chars = digit_chars.replace('0', '').replace('1', '')
        char_pool += digit_chars
        required_chars.append(secrets.choice(digit_chars))
    
    if use_symbol:
        symbol_chars = "!@#$%^&*-_+=."
        char_pool += symbol_chars
        required_chars.append(secrets.choice(symbol_chars))
    
    # 确保至少有一类字符被选中
    if not char_pool:
        char_pool = string.ascii_lowercase
        required_chars = [secrets.choice(string.ascii_lowercase)]
    
    # 填充剩余长度
    remaining = length - len(required_chars)
    if remaining > 0:
        required_chars.extend(
            secrets.choice(char_pool) for _ in range(remaining)
        )
    
    # 使用 secrets.SystemRandom().shuffle() 打乱顺序
    # 注意：secrets 模块没有 shuffle，使用 random.shuffle 但传入 secrets.SystemRandom()
    import random
    rng = secrets.SystemRandom()
    rng.shuffle(required_chars)
    
    password = ''.join(required_chars)
    
    # 估算熵值
    pool_size = len(char_pool)
    entropy = length * (pool_size.bit_length() - 1)  # 近似估算
    
    return password, float(entropy)


def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    include_number: bool = True,
    include_symbol: bool = True
) -> Tuple[str, float]:
    """
    生成易记的口令密码（Diceware风格）
    
    使用常用英文单词组合，易于口述和记忆
    
    Args:
        num_words: 单词数量（3-6）
        separator: 单词分隔符
        include_number: 末尾添加随机数字
        include_symbol: 末尾添加随机符号
    
    Returns:
        (生成的口令, 熵值估算)
    """
    # 简化版常用单词表（实际应使用更大的词表）
    WORD_LIST = [
        "apple", "banana", "cherry", "delta", "eagle", "flame", "grape",
        "honey", "igloo", "jungle", "kite", "lemon", "melon", "night",
        "ocean", "piano", "queen", "river", "snake", "tiger", "uncle",
        "violet", "whale", "xray", "yellow", "zebra", "anchor", "bridge",
        "castle", "dragon", "eagle", "forest", "garden", "harbor", "island",
        "jacket", "kitchen", "ladder", "market", "needle", "orange", "palace",
        "quilt", "rocket", "school", "tunnel", "umbrella", "valley", "window",
        "yellow", "zipper", "amber", "bronze", "crystal", "diamond", "emerald",
        "feather", "golden", "hammer", "iceberg", "jasmine", "knight", "lighthouse",
        "marble", "nectar", "obsidian", "pearl", "quartz", "ruby", "sapphire",
        "thunder", "unicorn", "volcano", "willow", "xenon", "yacht", "zenith"
    ]
    
    words = [secrets.choice(WORD_LIST) for _ in range(num_words)]
    
    if include_number:
        words.append(str(secrets.randbelow(100)))
    
    if include_symbol:
        words.append(secrets.choice("!@#$%"))
    
    password = separator.join(words)
    
    # 熵值估算：每个单词约6.5 bits（基于64词表），数字约6.6 bits
    entropy = num_words * 6.5 + (6.6 if include_number else 0) + (3.3 if include_symbol else 0)
    
    return password, entropy


def generate_memorable_password(
    num_words: int = 3,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True
) -> Tuple[str, float]:
    """
    生成易记且安全的密码（多词组合+变形）
    
    Args:
        num_words: 单词数量（2-4）
        separator: 分隔符
        capitalize: 随机大写某些单词
        add_number: 添加随机数字后缀
    
    Returns:
        (生成的密码, 熵值估算)
    """
    WORD_LIST = [
        "blue", "house", "running", "fast", "silent", "mountain", "river",
        "ocean", "forest", "desert", "winter", "summer", "spring", "autumn",
        "thunder", "lightning", "crystal", "shadow", "golden", "silver",
        "purple", "crimson", "azure", "emerald", "silent", "brave", "mighty",
        "gentle", "fierce", "calm", "wild", "free", "bright", "dark",
        "hidden", "secret", "ancient", "eternal", "infinite", "cosmic"
    ]
    
    words = [secrets.choice(WORD_LIST) for _ in range(num_words)]
    
    if capitalize:
        # 随机选择1-2个单词首字母大写
        num_to_cap = secrets.randbelow(2) + 1
        indices = secrets.SystemRandom().sample(range(num_words), min(num_to_cap, num_words))
        for i in indices:
            words[i] = words[i].capitalize()
    
    password = separator.join(words)
    
    if add_number:
        password += str(secrets.randbelow(1000))
    
    # 熵值估算
    entropy = num_words * 5.3 + (3.3 if capitalize else 0) + (9.9 if add_number else 0)
    
    return password, entropy


# 测试代码
if __name__ == "__main__":
    print("=" * 50)
    print("测试随机密码生成")
    print("=" * 50)
    
    pwd, ent = generate_random_password(length=16)
    print(f"随机密码: {pwd}")
    print(f"估算熵值: {ent:.1f} bits")
    
    print("\n" + "=" * 50)
    print("测试口令生成")
    print("=" * 50)
    
    pwd, ent = generate_passphrase(num_words=4)
    print(f"口令密码: {pwd}")
    print(f"估算熵值: {ent:.1f} bits")
    
    print("\n" + "=" * 50)
    print("测试易记密码生成")
    print("=" * 50)
    
    pwd, ent = generate_memorable_password(num_words=3)
    print(f"易记密码: {pwd}")
    print(f"估算熵值: {ent:.1f} bits")