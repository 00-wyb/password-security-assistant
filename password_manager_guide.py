
"""
密码管理器向导模块
提供主流密码管理器的使用指南
"""

from typing import Dict, List

# 密码管理器数据库
PASSWORD_MANAGERS = {
    "bitwarden": {
        "name": "Bitwarden",
        "type": "开源免费",
        "icon": "🔓",
        "url": "https://bitwarden.com",
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android", "浏览器扩展"],
        "features": ["端到端加密", "自托管选项", "免费版功能完整", "密码共享", "安全笔记"],
        "steps": [
            "访问 bitwarden.com 注册账户",
            "下载对应平台的客户端或浏览器扩展",
            "设置主密码（务必牢记，无法找回）",
            "创建新项目，粘贴生成的密码",
            "启用两步验证增强安全性"
        ],
        "pros": ["完全开源", "跨平台同步", "免费版无限制"],
        "cons": ["自托管需要技术基础"]
    },
    "1password": {
        "name": "1Password",
        "type": "商业软件",
        "icon": "🔐",
        "url": "https://1password.com",
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android", "浏览器扩展"],
        "features": ["旅行模式", "Watchtower安全监控", "密码共享", "SSH密钥管理"],
        "steps": [
            "访问 1password.com 订阅服务（个人/家庭/团队）",
            "下载客户端并安装",
            "创建账户并设置主密码",
            "使用浏览器扩展自动保存和填充密码",
            "开启Watchtower监控密码健康度"
        ],
        "pros": ["用户体验优秀", "安全功能丰富", "企业支持完善"],
        "cons": ["付费订阅", "不开源"]
    },
    "keepassxc": {
        "name": "KeePassXC",
        "type": "完全离线",
        "icon": "💾",
        "url": "https://keepassxc.org",
        "platforms": ["Windows", "macOS", "Linux"],
        "features": ["完全离线", "数据库文件自主控制", "无云服务", "插件扩展"],
        "steps": [
            "访问 keepassxc.org 下载安装",
            "创建新的密码数据库文件（.kdbx）",
            "设置数据库主密钥（密码+密钥文件可选）",
            "添加密码条目，手动输入或粘贴",
            "将数据库文件备份到安全位置（U盘/加密云盘）"
        ],
        "pros": ["完全免费", "数据完全自控", "无网络依赖"],
        "cons": ["无自动同步", "界面较简陋", "移动端需第三方客户端"]
    },
    "icloud_keychain": {
        "name": "iCloud钥匙串",
        "type": "苹果生态",
        "icon": "🍎",
        "url": "https://support.apple.com/zh-cn/HT204085",
        "platforms": ["iOS", "macOS", "iPadOS"],
        "features": ["系统集成", "自动填充", "密码生成", "跨设备同步"],
        "steps": [
            "打开设置 → Apple ID → iCloud",
            "开启'密码与钥匙串'",
            "在Safari中保存密码时会自动同步",
            "设置 → 密码中查看和管理已保存密码"
        ],
        "pros": ["无需额外安装", "与系统深度集成", "免费"],
        "cons": ["仅限苹果设备", "功能相对简单"]
    }
}


def get_manager_guide(manager_key: str) -> Dict:
    """获取指定密码管理器的指南"""
    return PASSWORD_MANAGERS.get(manager_key, PASSWORD_MANAGERS["bitwarden"])


def get_all_managers() -> List[Dict]:
    """获取所有密码管理器列表"""
    return [
        {"key": k, "name": v["name"], "type": v["type"], "icon": v["icon"]}
        for k, v in PASSWORD_MANAGERS.items()
    ]


def generate_save_guide(password: str, manager_key: str = "bitwarden") -> str:
    """
    生成针对特定密码的保存指南文本
    """
    manager = get_manager_guide(manager_key)

    guide = f"""
{'='*60}
🔐 密码安全保存指南
{'='*60}

推荐工具: {manager['icon']} {manager['name']} ({manager['type']})
官网: {manager['url']}

📋 保存步骤:
{' '.join(f'{i+1}. {step}' for i, step in enumerate(manager['steps']))}

⚠️ 重要提醒:
• 主密码是您唯一需要记住的密码，务必安全保管
• 建议将主密码写在纸上存放在安全位置
• 启用两步验证（2FA）以获得额外保护
• 定期备份密码数据库

{'='*60}
"""
    return guide