"""
批量密码评估模块
支持一次性评估多个密码，生成汇总报告
"""

from typing import List, Dict
from password_evaluator import evaluate_password
from hibp_client import check_pwned


def batch_evaluate(passwords: List[str], check_leak: bool = True) -> List[Dict]:
    """
    批量评估密码

    Args:
        passwords: 密码列表
        check_leak: 是否检查泄露（较慢，可选）

    Returns:
        评估结果列表
    """
    results = []

    for i, pwd in enumerate(passwords):
        if not pwd or not pwd.strip():
            continue

        pwd = pwd.strip()

        # 评估强度
        eval_result = evaluate_password(pwd)

        # 检查泄露（可选，避免过多API调用）
        is_pwned = False
        pwned_count = 0
        if check_leak:
            try:
                is_pwned, pwned_count = check_pwned(pwd)
            except Exception:
                pwned_count = -1  # 查询失败

        # 脱敏显示
        masked = pwd[:2] + "***" + pwd[-2:] if len(pwd) > 4 else "****"

        results.append({
            "index": i + 1,
            "masked": masked,
            "length": len(pwd),
            "score": eval_result["score"],
            "level": eval_result["level"],
            "color": eval_result["color"],
            "entropy": eval_result["entropy"],
            "is_pwned": is_pwned,
            "pwned_count": pwned_count,
            "char_types": eval_result["char_types"],
            "patterns_found": eval_result["patterns_found"],
            "suggestions": eval_result["suggestions"]
        })

    return results


def batch_summary(results: List[Dict]) -> Dict:
    """
    生成批量评估汇总统计
    """
    if not results:
        return {}

    total = len(results)
    scores = [r["score"] for r in results]
    pwned_count = sum(1 for r in results if r["is_pwned"])
    failed_checks = sum(1 for r in results if r["pwned_count"] == -1)

    # 等级分布
    level_counts = {}
    for r in results:
        level = r["level"]
        level_counts[level] = level_counts.get(level, 0) + 1

    # 风险密码（弱或已泄露）
    risky_passwords = [
        r for r in results 
        if r["score"] < 40 or r["is_pwned"]
    ]

    return {
        "total": total,
        "average_score": round(sum(scores) / total, 1),
        "max_score": max(scores),
        "min_score": min(scores),
        "weak_count": sum(1 for s in scores if s < 40),
        "medium_count": sum(1 for s in scores if 40 <= s < 70),
        "strong_count": sum(1 for s in scores if s >= 70),
        "pwned_count": pwned_count,
        "failed_checks": failed_checks,
        "level_distribution": level_counts,
        "risky_count": len(risky_passwords),
        "risky_passwords": risky_passwords,
        "overall_risk": "高" if pwned_count > 0 or any(s < 40 for s in scores) else "中" if any(s < 70 for s in scores) else "低"
    }


def export_batch_csv(results: List[Dict]) -> str:
    """
    生成CSV格式的批量评估报告
    """
    lines = [
        "序号,密码(脱敏),长度,评分,等级,熵值,泄露状态,泄露次数,主要风险"
    ]

    for r in results:
        leak_status = "已泄露" if r["is_pwned"] else "未泄露" if r["pwned_count"] >= 0 else "查询失败"
        risk = ";".join(r["patterns_found"]) if r["patterns_found"] else "无"
        lines.append(
            f"{r['index']},{r['masked']},{r['length']},{r['score']},{r['level']},"
            f"{r['entropy']},{leak_status},{r['pwned_count']},{risk}"
        )

    return "\n".join(lines)