# 🔐 智能密码安全助手

基于AI增强的密码强度评估、泄露检测与密码生成工具，零持久化存储保障隐私。

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.58-red)
![License](https://img.shields.io/badge/License-MIT-green)

## ✨ 功能特性

- 🔍 **密码强度评估**：多维度规则引擎（长度、复杂度、模式、熵值）
- 🔎 **泄露检测**：集成 Have I Been Pwned 数据库，k-匿名查询
- 🤖 **AI风险解析**：智谱GLM-4 智能分析风险与改进建议
- 🔑 **密码生成器**：随机密码 / 口令密码 / 易记密码三种模式
- 🔒 **隐私优先**：零登录、零持久化、即时销毁

## 🚀 快速开始

### 本地运行

```bash
# 1. 克隆仓库
git clone https://github.com/your-username/password-security-assistant.git
cd password-security-assistant

# 2. 创建虚拟环境
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置API密钥
# 创建 .streamlit/secrets.toml
echo 'ZHIPU_API_KEY = "your-api-key"' &gt; .streamlit/secrets.toml

# 5. 运行
streamlit run app.py