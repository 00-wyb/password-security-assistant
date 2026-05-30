"""
智能密码安全助手 - Day 2 版本
功能：密码泄露查询 + 密码强度评估
"""

import streamlit as st
from hibp_client import check_pwned
from password_evaluator import evaluate_password


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

password = st.text_input(
    label="输入密码",
    type="password",
    placeholder="输入或粘贴要检测的密码...",
    label_visibility="collapsed",
    help="密码将被安全处理，不会被保存"
)

col1, col2 = st.columns(2)
with col1:
    check_pwned_btn = st.button("🔍 检测泄露", type="primary", use_container_width=True)
with col2:
    evaluate_btn = st.button("📊 评估强度", type="secondary", use_container_width=True)


# ========== 结果显示区域 ==========
if password and (check_pwned_btn or evaluate_btn):
    
    if len(password) < 1:
        st.warning("请输入密码")
    else:
        with st.spinner("正在分析..."):
            
            # 执行评估（两个按钮都触发评估，泄露检测额外查HIBP）
            eval_result = evaluate_password(password)
            
            # ========== 综合评分展示 ==========
            st.divider()
            
            # 评分大数字
            score_col, info_col = st.columns([1, 2])
            
            with score_col:
                st.markdown(f"""
                <div style="
                    text-align: center;
                    padding: 1rem;
                ">
                    <div style="
                        font-size: 3rem;
                        font-weight: bold;
                        color: {eval_result['color']};
                    ">{eval_result['score']}</div>
                    <div style="
                        font-size: 1.2rem;
                        color: {eval_result['color']};
                        font-weight: 600;
                    ">{eval_result['level']}</div>
                    <div style="font-size: 0.8rem; color: #888;">/ 100</div>
                </div>
                """, unsafe_allow_html=True)
            
            with info_col:
                # 进度条
                st.progress(eval_result['score'] / 100)
                
                # 基本信息
                st.write(f"**长度**: {eval_result['length']} 位")
                st.write(f"**字符种类**: {eval_result['char_types']}/4 "
                        f"(小写{'✓' if eval_result['has_lower'] else '✗'} "
                        f"大写{'✓' if eval_result['has_upper'] else '✗'} "
                        f"数字{'✓' if eval_result['has_digit'] else '✗'} "
                        f"符号{'✓' if eval_result['has_symbol'] else '✗'})")
                st.write(f"**熵值**: {eval_result['entropy']} bits")
            
            # ========== 维度拆解 ==========
            st.subheader("📊 维度拆解")
            
            dim_col1, dim_col2, dim_col3, dim_col4 = st.columns(4)
            
            with dim_col1:
                st.metric("长度", f"{eval_result['length_score']}/40", 
                         delta="✓" if eval_result['length_score'] >= 15 else "✗")
            with dim_col2:
                st.metric("复杂度", f"{eval_result['complexity_score']}/30",
                         delta="✓" if eval_result['complexity_score'] >= 21 else "✗")
            with dim_col3:
                st.metric("模式安全", f"{eval_result['pattern_score']}/30",
                         delta="✓" if eval_result['pattern_score'] >= 20 else "✗")
            with dim_col4:
                st.metric("熵值", f"{eval_result['entropy_score']}/25",
                         delta="✓" if eval_result['entropy_score'] >= 10 else "✗")
            
            # ========== 风险模式警告 ==========
            if eval_result['patterns_found']:
                st.warning(f"⚠️ 检测到风险模式: {', '.join(eval_result['patterns_found'])}")
            
            # ========== 泄露检测（仅点击检测泄露时） ==========
            if check_pwned_btn:
                st.divider()
                st.subheader("🔍 泄露检测")
                
                is_pwned, count = check_pwned(password)
                
                if count == -1:
                    st.error("❌ 查询失败")
                    st.info("HIBP 服务暂时不可用，请稍后重试。")
                elif is_pwned:
                    st.error(f"🚨 **该密码已泄露 {count:,} 次！**")
                    st.markdown("""
                    <div style="background-color: #fee2e2; border-left: 4px solid #ef4444; padding: 1rem; border-radius: 4px;">
                        <h4 style="color: #dc2626; margin-top: 0;">⚠️ 紧急建议</h4>
                        <ul>
                            <li>请<strong>立即</strong>在所有使用该密码的网站上更换密码</li>
                            <li>不要仅做简单修改（如加数字、改大小写）</li>
                            <li>使用密码生成器创建全新的强密码</li>
                        </ul>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.success("✅ **未在泄露数据库中发现**")
            
            # ========== 改进建议 ==========
            st.divider()
            st.subheader("💡 改进建议")
            
            for i, suggestion in enumerate(eval_result['suggestions'], 1):
                st.write(f"{i}. {suggestion}")
            
            # 隐私说明
            st.caption("🔒 本次分析已完成，密码已从内存中清除")


# ========== 底部信息 ==========
st.divider()
st.caption("""
<div style="text-align: center; color: #888;">
    数据来源: <a href="https://haveibeenpwned.com" target="_blank">Have I Been Pwned</a> |
    使用 k-匿名技术保护您的隐私 |
    <a href="#" target="_blank">隐私政策</a>
</div>
""", unsafe_allow_html=True)