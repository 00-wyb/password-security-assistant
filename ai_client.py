"""
智谱AI API客户端
实现密码安全分析的AI增强功能
关键约束：绝不传输密码明文或哈希
支持新版密钥格式：无sk-前缀的直接字符串
"""

import requests
import json
from typing import Dict, Optional


class AIClient:
    """
    AI客户端，用于生成密码风险解释和改进建议
    支持智谱GLM-4 API，新版密钥格式：e980...Yftv（无sk-前缀）
    """
    
    def __init__(self, api_key: str, base_url: str = "https://open.bigmodel.cn/api/paas/v4"):
        if not api_key:
            raise ValueError("API密钥不能为空")
        self.api_key = api_key
        self.base_url = base_url
        self.model = "glm-4"
    
    def analyze_password(self, 
                        score: int,
                        length: int,
                        char_types: int,
                        entropy: float,
                        is_pwned: bool,
                        pwned_count: int = 0,
                        patterns_found: Optional[list] = None,
                        level: str = "") -> Dict[str, str]:
        """
        基于脱敏特征生成AI风险分析
        
        Args:
            score: 综合评分(0-100)
            length: 密码长度
            char_types: 字符种类数(1-4)
            entropy: 熵值
            is_pwned: 是否已泄露
            pwned_count: 泄露次数
            patterns_found: 检测到的风险模式
            level: 等级标签
        
        Returns:
            {
                'risk_explanation': '风险解释',
                'improvement_advice': '改进建议',
                'security_tips': '安全小贴士'
            }
        """
        
        # 构建脱敏特征描述
        pwned_status = f"已泄露 {pwned_count:,} 次" if is_pwned else "未泄露"
        
        patterns_text = ""
        if patterns_found:
            patterns_text = f"检测到的风险模式: {', '.join(patterns_found)}"
        
        # 构建提示词
        system_prompt = """你是一位资深的密码安全专家，擅长用通俗易懂的语言解释密码安全风险。
你的任务是根据密码的评估特征（绝不包含密码本身），生成专业的风险分析和改进建议。
要求：
1. 语气专业但易懂，适合非技术用户
2. 分析具体，指出核心问题
3. 建议可操作，避免空泛
4. 若密码已泄露，强调紧急性
5. 若密码强度好，给予肯定并提醒持续保护
6. 总字数控制在200字以内"""

        user_prompt = f"""请根据以下密码评估结果生成分析：

【评估特征】
- 综合评分: {score}/100（等级: {level}）
- 密码长度: {length} 位
- 字符种类: {char_types}/4（小写/大写/数字/符号）
- 熵值: {entropy} bits
- 泄露状态: {pwned_status}
{patterns_text}

请生成三部分内容：
1. 【风险解释】：为什么这个密码是当前的等级，核心问题是什么
2. 【改进建议】：1-2条具体可操作的改进措施
3. 【安全贴士】：一条相关的密码安全知识

用中文输出，格式清晰。"""

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",  # 直接用密钥，不加sk-
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 400,
                    "top_p": 0.8
                },
                timeout=15
            )
            
            if response.status_code != 200:
                print(f"AI API错误: {response.status_code}, {response.text}")
                return self._fallback_response(score, is_pwned, level)
            
            result = response.json()
            ai_content = result["choices"][0]["message"]["content"]
            
            # 解析AI返回的内容
            return self._parse_ai_response(ai_content)
            
        except requests.exceptions.Timeout:
            print("AI API请求超时")
            return self._fallback_response(score, is_pwned, level)
        except Exception as e:
            print(f"AI API请求失败: {e}")
            return self._fallback_response(score, is_pwned, level)
    
    def _parse_ai_response(self, content: str) -> Dict[str, str]:
        """
        解析AI返回的文本，提取三部分内容
        """
        risk_explanation = ""
        improvement_advice = ""
        security_tips = ""
        
        lines = content.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if '风险解释' in line or '【风险解释】' in line:
                current_section = 'risk'
                continue
            elif '改进建议' in line or '【改进建议】' in line:
                current_section = 'advice'
                continue
            elif '安全贴士' in line or '【安全贴士】' in line or '安全知识' in line:
                current_section = 'tips'
                continue
            
            if current_section == 'risk':
                risk_explanation += line + " "
            elif current_section == 'advice':
                improvement_advice += line + " "
            elif current_section == 'tips':
                security_tips += line + " "
        
        # 清理并设置默认值
        risk_explanation = risk_explanation.strip() or "该密码存在一定安全风险，建议根据评分进行优化。"
        improvement_advice = improvement_advice.strip() or "建议增加密码长度和复杂度，避免常见模式。"
        security_tips = security_tips.strip() or "定期更换密码，不要在多个网站使用相同密码。"
        
        return {
            'risk_explanation': risk_explanation,
            'improvement_advice': improvement_advice,
            'security_tips': security_tips
        }
    
    def _fallback_response(self, score: int, is_pwned: bool, level: str) -> Dict[str, str]:
        """
        AI故障时的降级响应（静态模板）
        """
        if is_pwned:
            return {
                'risk_explanation': f'该密码已泄露，评分仅{score}分（{level}）。泄露的密码已被攻击者收录，面临极高的被利用风险。',
                'improvement_advice': '1. 立即在所有使用该密码的网站更换密码；2. 使用密码生成器创建全新的、唯一的强密码。',
                'security_tips': '已泄露的密码即使修改一两个字符也不安全，必须完全更换。'
            }
        elif score < 40:
            return {
                'risk_explanation': f'该密码评分仅{score}分（{level}），存在明显安全缺陷，容易被暴力破解或字典攻击。',
                'improvement_advice': '1. 增加密码长度至16位以上；2. 混合使用大小写字母、数字和符号；3. 避免使用常见单词和序列。',
                'security_tips': '长度比复杂度更重要，一个20位的随机短语比8位的复杂符号密码更安全。'
            }
        elif score < 70:
            return {
                'risk_explanation': f'该密码评分{score}分（{level}），基本可用但仍有提升空间，面对针对性攻击可能不够安全。',
                'improvement_advice': '1. 增加长度或添加特殊符号；2. 检查是否存在不易察觉的模式（如键盘路径）。',
                'security_tips': '建议为重要账户（邮箱、银行）使用独立的强密码，并启用双因素认证。'
            }
        else:
            return {
                'risk_explanation': f'该密码评分{score}分（{level}），强度良好，能有效抵御常见的暴力破解和字典攻击。',
                'improvement_advice': '继续保持！建议启用双因素认证（2FA）以获得额外保护。',
                'security_tips': '即使强密码也应定期更换（建议每年一次），并确保每个网站使用唯一密码。'
            }


# 测试代码
if __name__ == "__main__":
    import os
    
    # 测试降级模式（无需密钥）
    print("=" * 50)
    print("测试降级模式")
    print("=" * 50)
    client = AIClient("dummy-key")
    result = client._fallback_response(25, False, "弱")
    print(f"\n风险解释: {result['risk_explanation'][:50]}...")
    print(f"改进建议: {result['improvement_advice'][:50]}...")
    
    # 测试真实AI（如果有密钥）
    api_key = os.getenv("ZHIPU_API_KEY", "")
    if api_key:
        print("\n" + "=" * 50)
        print("测试真实AI调用")
        print("=" * 50)
        
        client = AIClient(api_key)
        
        test_case = {
            'score': 15,
            'length': 6,
            'char_types': 1,
            'entropy': 19.9,
            'is_pwned': True,
            'pwned_count': 3847,
            'patterns_found': ['数字序列'],
            'level': '极弱'
        }
        
        result = client.analyze_password(**test_case)
        print(f"\n风险解释: {result['risk_explanation']}")
        print(f"\n改进建议: {result['improvement_advice']}")
        print(f"\n安全贴士: {result['security_tips']}")
    else:
        print("\n未配置ZHIPU_API_KEY，跳过真实AI测试")
        print("如需测试，设置环境变量:")
        print("  Windows: set ZHIPU_API_KEY=e980...Yftv")
        print("  macOS/Linux: export ZHIPU_API_KEY=e980...Yftv")