# 🔐 智能密码安全助手（AI-Powered Password Health Guardian）

基于AI增强的密码强度评估、泄露检测与密码生成工具，**零持久化存储**保障隐私。

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.58-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🌐 在线演示

**👉 [点击访问在线应用](https://password-assistant.streamlit.app)**

无需安装，打开即用，零登录、零注册。

---

## ✨ 功能特性

### 核心功能
- 🔍 **密码强度评估**：多维度规则引擎（长度、复杂度、模式、熵值）
- 🔎 **泄露检测**：集成 Have I Been Pwned 数据库，**k-匿名查询**保护隐私
- 🤖 **AI风险解析**：智谱GLM-4 智能分析风险与改进建议
- 🔑 **密码生成器**：随机密码 / 口令密码 / 易记密码三种模式

### 增强功能
- 📋 **批量评估**：一次性评估50个密码，生成汇总报告
- 🏷️ **场景标签**：通用/邮箱/金融/工作场景化安全评估
- ⚖️ **密码对比**：新旧密码安全对比，直观展示提升效果
- 💾 **管理器向导**：Bitwarden/1Password/KeePassXC/iCloud使用指南
- 💡 **实时提示**：输入时即时显示强度反馈和改进建议

---

## 🔒 隐私与安全

### 我们的承诺
- ✅ **零登录**：无需注册，不收集任何个人信息
- ✅ **零持久化**：服务端不保存密码到磁盘或数据库
- ✅ **即时销毁**：每次请求独立处理，响应后内存释放

### 诚实声明
&gt; ⚠️ **密码在处理请求时会经过 Streamlit Cloud 服务端内存**，但：
&gt; - 不做任何持久化存储
&gt; - 不记录访问日志
&gt; - AI分析仅接收脱敏后的统计特征（评分、长度、熵值），**绝不包含密码明文**
&gt; - 代码开源可审计

### 建议
- 在**私密网络环境**下使用
- 避免在**公共设备**上使用
- 使用后点击**"清除数据"**按钮主动清理

---

## 🏗️ 技术架构

**技术栈**：Python 3.11 + Streamlit + 智谱GLM-4 + Have I Been Pwned API

---

## 🚀 快速开始

### 方式一：在线使用（推荐）

直接访问：[https://password-assistant.streamlit.app](https://password-assistant.streamlit.app)

### 方式二：本地运行

```bash
# 1. 克隆仓库
git clone https://github.com/00-wyb/password-security-assistant.git
cd password-security-assistant

# 2. 创建虚拟环境
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置API密钥
# 创建 .streamlit/secrets.toml
echo 'ZHIPU_API_KEY = "your-api-key"' > .streamlit/secrets.toml

# 5. 运行
streamlit run app.py