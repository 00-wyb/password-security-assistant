"""
智能密码安全助手 - Day 1 版本
功能：密码泄露查询（Have I Been Pwned）
"""

import streamlit as st
from hibp_client import check_pwned


# ========== 页面配置 ==========
st.set_page_config(
    page_title="智能密码安全助手",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)


# ========== 安全提示横幅 ==========
st.markdown("""
<div style="
    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 1rem;
    border-radius: 10px;
    text-align: center;
    margin-bottom: 2rem;
    font-size: 0.9rem;
">
    🔒 <b>零登录 · 零持久化 · 隐私优先</b><br>
    密码仅在服务端内存中处理，响应后立即销毁，不做任何存储
</div>
""", unsafe_allow_html=True)


# ========== 主标题 ==========
st.markdown("<h1 style='text-align: center;'>🔐 智能密码安全助手</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #666;'>基于 AI 增强的密码安全检测工具</p>", unsafe_allow_html=True)


# ========== 密码输入区域 ==========
st.divider()

col_input, col_button = st.columns([3, 1])

with col_input:
    password = st.text_input(
        label="输入密码",
        type="password",
        placeholder="输入或粘贴要检测的密码...",
        label_visibility="collapsed",
        help="密码将被安全处理，不会被保存"
    )

with col_button:
    # 垂直对齐按钮
    st.write("")  # 占位
    st.write("")  # 占位
    check_clicked = st.button(
        "🔍 检测泄露",
        type="primary",
        use_container_width=True
    )


# ========== 结果显示区域 ==========
if check_clicked and password:
    
    # 验证输入
    if len(password) < 1:
        st.warning("请输入密码")
    else:
        with st.spinner("正在查询 Have I Been Pwned 数据库..."):
            
            # 调用 HIBP 查询
            is_pwned, count = check_pwned(password)
            
            # 显示结果
            st.divider()
            
            if count == -1:
                # 查询失败
                st.error("❌ 查询失败")
                st.info("HIBP 服务暂时不可用，请稍后重试。您的密码未被记录。")
                
            elif is_pwned:
                # 已泄露
                st.error(f"🚨 **该密码已泄露 {count:,} 次！**")
                
                st.markdown(f"""
                <div style="
                    background-color: #fee2e2;
                    border-left: 4px solid #ef4444;
                    padding: 1rem;
                    border-radius: 4px;
                    margin: 1rem 0;
                ">
                    <h4 style="color: #dc2626; margin-top: 0;">⚠️ 紧急建议</h4>
                    <ul style="margin-bottom: 0;">
                        <li>请<strong>立即</strong>在所有使用该密码的网站上更换密码</li>
                        <li>不要仅做简单修改（如加数字、改大小写）</li>
                        <li>使用密码生成器创建全新的强密码</li>
                        <li>检查是否在其他账户上重复使用了该密码</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)
                
            else:
                # 未泄露
                st.success("✅ **未在泄露数据库中发现**")
                
                st.markdown("""
                <div style="
                    background-color: #d1fae5;
                    border-left: 4px solid #10b981;
                    padding: 1rem;
                    border-radius: 4px;
                    margin: 1rem 0;
                ">
                    <h4 style="color: #059669; margin-top: 0;">✓ 好消息</h4>
                    <p style="margin-bottom: 0;">
                        该密码未出现在已知的泄露数据库中。<br>
                        但这不代表密码足够安全，建议继续使用强度评估功能检测。
                    </p>
                </div>
                """, unsafe_allow_html=True)
            
            # 隐私说明
            st.caption("🔒 本次查询已完成，密码已从内存中清除")


# ========== 底部信息 ==========
st.divider()
st.caption("""
<div style="text-align: center; color: #888;">
    数据来源: <a href="https://haveibeenpwned.com" target="_blank">Have I Been Pwned</a> |
    使用 k-匿名技术保护您的隐私 |
    <a href="#" target="_blank">隐私政策</a>
</div>
""", unsafe_allow_html=True)