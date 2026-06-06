"""
场景配置模块
定义不同使用场景的安全要求和评分权重
"""

from typing import Dict

# 场景定义
SCENARIOS = {
    "general": {
        "name": "通用",
        "description": "一般网站和应用",
        "min_score": 40,
        "recommended_score": 70,
        "leak_sensitivity": "中",
        "weight_adjustments": {},
        "icon": "🌐"
    },
    "email_social": {
        "name": "邮箱/社交",
        "description": "邮箱、社交媒体账户",
        "min_score": 70,
        "recommended_score": 85,
        "leak_sensitivity": "极高",
        "weight_adjustments": {"length": 1.2, "complexity": 1.1},
        "icon": "📧",
        "warning": "邮箱密码泄露可能导致所有关联账户被接管"
    },
    "banking_payment": {
        "name": "网银/支付",
        "description": "银行、支付平台",
        "min_score": 90,
        "recommended_score": 95,
        "leak_sensitivity": "极高",
        "weight_adjustments": {"length": 1.3, "complexity": 1.2, "entropy": 1.2},
        "icon": "💳",
        "warning": "金融账户密码必须极强，建议启用硬件密钥"
    },
    "work_enterprise": {
        "name": "工作/企业",
        "description": "企业系统、工作邮箱",
        "min_score": 70,
        "recommended_score": 85,
        "leak_sensitivity": "高",
        "weight_adjustments": {"length": 1.1, "complexity": 1.1},
        "icon": "🏢",
        "warning": "企业密码泄露可能导致数据泄露和法律责任"
    },
    "other": {
        "name": "其他",
        "description": "其他特殊场景",
        "min_score": 40,
        "recommended_score": 70,
        "leak_sensitivity": "中",
        "weight_adjustments": {},
        "icon": "📌"
    }
}


def get_scenario_config(scenario_key: str) -> Dict:
    """获取场景配置"""
    return SCENARIOS.get(scenario_key, SCENARIOS["general"])


def get_scenario_adjusted_score(base_score: int, scenario_key: str) -> int:
    """
    根据场景调整评分
    某些场景对评分要求更严格
    """
    config = get_scenario_config(scenario_key)

    # 如果评分低于场景最低要求，降低显示分数以引起注意
    if base_score < config["min_score"]:
        # 线性降低，最低降至原分的70%
        penalty = (config["min_score"] - base_score) / config["min_score"] * 0.3
        adjusted = int(base_score * (1 - penalty))
        return max(0, adjusted)

    return base_score


def get_scenario_status(score: int, scenario_key: str) -> Dict:
    """
    获取密码在特定场景下的状态
    """
    config = get_scenario_config(scenario_key)

    if score >= config["recommended_score"]:
        status = "excellent"
        color = "#059669"
        message = f"✅ 符合{config['name']}场景推荐标准"
    elif score >= config["min_score"]:
        status = "acceptable"
        color = "#f59e0b"
        message = f"⚠️ 达到{config['name']}场景最低要求，建议提升至{config['recommended_score']}分"
    else:
        status = "danger"
        color = "#dc2626"
        message = f"🚨 未达到{config['name']}场景安全要求（最低{config['min_score']}分）"

    return {
        "status": status,
        "color": color,
        "message": message,
        "min_score": config["min_score"],
        "recommended_score": config["recommended_score"],
        "warning": config.get("warning", "")
    }