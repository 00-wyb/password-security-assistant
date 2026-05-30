"""
智能密码安全助手 - Day 4 版本

功能：密码泄露查询 + 密码强度评估 + AI智能分析 + 密码生成器
架构：隐私优先（零登录、零持久化、即时销毁）
"""

import streamlit as st
import html
from hibp_client import check_pwned
from password_evaluator import evaluate_password
from ai_client import AIClient
from password_generator import generate_random_password, generate_passphrase, generate_memorable_password


# ========== 页面配置 ==========
st.set_page_config(
    page_title="智能密码安全助手",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)


# ========== 安全工具函数 ==========
def safe_html(text: str) -> str:
    """对文本进行HTML转义，防止XSS攻击"""
    return html.escape(text) if text else ""


# ========== 初始化AI客户端 ==========
@st.cache_resource
def get_ai_client():
    """缓存AI客户端，避免重复初始化"""
    try:
        api_key = st.secrets["ZHIPU_API_KEY"]
        base_url = st.secrets.get("AI_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
        return AIClient(api_key, base_url)
    except Exception as e:
        return None


ai_client = get_ai_client()


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
st.markdown("<p style='text-align: center; color: #666;'>基于AI增强的密码安全检测工具</p>", unsafe_allow_html=True)


# ========== 标签页设计 ==========
tab1, tab2, tab3 = st.tabs(["🔍 评估密码", "🔑 生成密码", "📖 安全指南"])


# ========== Tab 1: 密码评估 ==========
with tab1:
    st.header("🔍 密码强度评估")
    
    # 密码输入（增加长度限制）
    password = st.text_input(
        label="输入密码",
        type="password",
        placeholder="输入或粘贴要检测的密码...",
        label_visibility="collapsed",
        help="密码将被安全处理，不会被保存（最大128字符）",
        max_chars=128  # 限制输入长度，防止DoS
    )
    
    # 选项
    check_leak = st.checkbox("同时检测是否泄露（需要联网）", value=True)
    
    col1, col2 = st.columns([1, 3])
    with col1:
        evaluate_btn = st.button("📊 开始评估", type="primary", use_container_width=True)
    with col2:
        if st.button("🧹 清除数据", use_container_width=True):
            # 清除所有可能包含密码的session state
            for key in list(st.session_state.keys()):
                if 'password' in key.lower() or 'pwd' in key.lower():
                    del st.session_state[key]
            st.rerun()
    
    if evaluate_btn and password:
        if len(password) < 1:
            st.warning("请输入密码")
        else:
            with st.spinner("正在分析..."):
                # 执行评估
                eval_result = evaluate_password(password)
                
                # HIBP查询（如果勾选）
                is_pwned = False
                pwned_count = 0
                if check_leak:
                    is_pwned, pwned_count = check_pwned(password)
                
                # ========== 综合评分展示 ==========
                st.divider()
                score_col, info_col = st.columns([1, 2])
                
                with score_col:
                    st.markdown(f"""
                    <div style="text-align: center; padding: 1rem;">
                        <div style="font-size: 3rem; font-weight: bold; color: {eval_result['color']};">
                            {eval_result['score']}
                        </div>
                        <div style="font-size: 1.2rem; color: {eval_result['color']}; font-weight: 600;">
                            {safe_html(eval_result['level'])}
                        </div>
                        <div style="font-size: 0.8rem; color: #888;">/ 100</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with info_col:
                    st.progress(eval_result['score'] / 100)
                    st.write(f"**长度**: {eval_result['length']} 位")
                    st.write(f"**字符种类**: {eval_result['char_types']}/4 "
                            f"(小写{'✓' if eval_result['has_lower'] else '✗'} "
                            f"大写{'✓' if eval_result['has_upper'] else '✗'} "
                            f"数字{'✓' if eval_result['has_digit'] else '✗'} "
                            f"符号{'✓' if eval_result['has_symbol'] else '✗'})")
                    st.write(f"**熵值**: {eval_result['entropy']} bits")
                
                # ========== 泄露状态 ==========
                if check_leak:
                    st.divider()
                    st.subheader("🔍 泄露检测")
                    
                    if pwned_count == -1:
                        st.error("⚠️ 查询失败")
                        st.info("HIBP服务暂时不可用，请稍后重试。")
                    elif is_pwned:
                        st.error(f"🚨 **该密码已泄露 {pwned_count:,} 次！**")
                        st.markdown("""
                        <div style="background-color: #fee2e2; border-left: 4px solid #ef4444; 
                                    padding: 1rem; border-radius: 4px;">
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
                
                # ========== 维度拆解 ==========
                st.divider()
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
                
                # ========== AI智能分析 ==========
                st.divider()
                st.subheader("🤖 AI风险深度解析")
                
                if ai_client:
                    with st.spinner("AI正在分析..."):
                        ai_result = ai_client.analyze_password(
                            score=eval_result['score'],
                            length=eval_result['length'],
                            char_types=eval_result['char_types'],
                            entropy=eval_result['entropy'],
                            is_pwned=is_pwned,
                            pwned_count=pwned_count,
                            patterns_found=eval_result['patterns_found'],
                            level=eval_result['level']
                        )
                else:
                    ai_result = AIClient("dummy")._fallback_response(
                        eval_result['score'], is_pwned, eval_result['level']
                    )
                    st.info("💡 AI服务未配置，显示预设建议。如需AI分析，请在Secrets中配置API密钥。")
                
                # 使用safe_html防止XSS
                st.markdown(f"""
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; 
                            border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                    <h4 style="color: #475569; margin-top: 0;">🔍 风险解释</h4>
                    <p style="color: #334155; line-height: 1.6;">
                        {safe_html(ai_result['risk_explanation'])}
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"""
                <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; 
                            border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                    <h4 style="color: #166534; margin-top: 0;">💡 改进建议</h4>
                    <p style="color: #14532d; line-height: 1.6;">
                        {safe_html(ai_result['improvement_advice'])}
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"""
                <div style="background-color: #eff6ff; border: 1px solid #bfdbfe; 
                            border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                    <h4 style="color: #1e40af; margin-top: 0;">📚 安全小贴士</h4>
                    <p style="color: #1e3a8a; line-height: 1.6;">
                        {safe_html(ai_result['security_tips'])}
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                # ========== 快速改进清单 ==========
                st.divider()
                st.subheader("📋 快速改进清单")
                for i, suggestion in enumerate(eval_result['suggestions'], 1):
                    st.write(f"{i}. {safe_html(suggestion)}")
                
                # 隐私说明
                st.caption("🔒 本次分析已完成，密码已从内存中清除")


# ========== Tab 2: 密码生成器 ==========
with tab2:
    st.header("🔑 智能密码生成器")
    
    # 生成模式选择
    gen_mode = st.radio(
        "生成模式",
        ["随机密码（最安全）", "口令密码（易记）", "易记密码（单词组合）"],
        horizontal=True
    )
    
    # 根据模式显示不同参数
    if gen_mode == "随机密码（最安全）":
        col1, col2 = st.columns(2)
        with col1:
            gen_length = st.slider("长度", 8, 32, 16)
        with col2:
            gen_strength = st.selectbox("目标强度", ["强", "极强"], index=0)
        
        # 字符类型
        st.write("字符类型:")
        col_c1, col_c2, col_c3, col_c4 = st.columns(4)
        with col_c1: use_lower = st.checkbox("小写字母", True, key="g_lower")
        with col_c2: use_upper = st.checkbox("大写字母", True, key="g_upper")
        with col_c3: use_digit = st.checkbox("数字", True, key="g_digit")
        with col_c4: use_symbol = st.checkbox("符号", True, key="g_symbol")
        
        # 高级选项
        st.write("高级选项:")
        exclude_ambiguous = st.checkbox("排除易混淆字符 (0/O/1/l/I)", True, key="g_ambig")
        
        if st.button("✨ 生成随机密码", type="primary"):
            with st.spinner("生成中..."):
                # 根据目标强度调整长度
                if gen_strength == "极强" and gen_length < 20:
                    gen_length = 20
                
                pwd, entropy = generate_random_password(
                    length=gen_length,
                    use_upper=use_upper,
                    use_lower=use_lower,
                    use_digit=use_digit,
                    use_symbol=use_symbol,
                    exclude_ambiguous=exclude_ambiguous
                )
                
                # 自动评估
                from password_evaluator import evaluate_password
                eval_result = evaluate_password(pwd)
                
                # 显示结果
                st.code(pwd, language=None)
                
                col_g1, col_g2, col_g3 = st.columns(3)
                with col_g1:
                    st.button("📋 复制", key="copy_random", 
                             on_click=lambda: st.write("已复制到剪贴板！"))
                with col_g2:
                    if st.button("🔄 重新生成", key="regen_random"):
                        st.rerun()
                with col_g3:
                    # 将生成的密码传递到评估页
                    if st.button("📊 评估此密码", key="eval_random"):
                        st.session_state['eval_password'] = pwd
                        st.info("请切换到「评估密码」标签页查看详细分析")
                
                st.write(f"**评分**: {eval_result['score']}/100 ({eval_result['level']})")
                st.write(f"**熵值**: {entropy:.1f} bits")
                st.write(f"**预计破解时间**: {'>10¹⁵ 年' if entropy > 60 else '>10⁹ 年' if entropy > 45 else '数年'}")
    
    elif gen_mode == "口令密码（易记）":
        col1, col2 = st.columns(2)
        with col1:
            num_words = st.slider("单词数量", 3, 6, 4)
        with col2:
            separator = st.selectbox("分隔符", ["-", "_", ".", " "], index=0)
        
        include_number = st.checkbox("添加随机数字", True, key="pp_num")
        include_symbol = st.checkbox("添加随机符号", True, key="pp_sym")
        
        if st.button("✨ 生成口令", type="primary"):
            with st.spinner("生成中..."):
                pwd, entropy = generate_passphrase(
                    num_words=num_words,
                    separator=separator,
                    include_number=include_number,
                    include_symbol=include_symbol
                )
                
                st.code(pwd, language=None)
                
                col_g1, col_g2 = st.columns(2)
                with col_g1:
                    st.button("📋 复制", key="copy_pp")
                with col_g2:
                    if st.button("🔄 重新生成", key="regen_pp"):
                        st.rerun()
                
                st.write(f"**熵值**: {entropy:.1f} bits")
                st.info("💡 口令密码由常见单词组成，易于记忆但安全性略低于完全随机密码")
    
    else:  # 易记密码（单词组合）
        col1, col2 = st.columns(2)
        with col1:
            num_words = st.slider("单词数量", 2, 4, 3)
        with col2:
            separator = st.selectbox("分隔符", ["-", "_", "."], index=0)
        
        capitalize = st.checkbox("随机大写", True, key="mem_cap")
        add_number = st.checkbox("添加数字后缀", True, key="mem_num")
        
        if st.button("✨ 生成易记密码", type="primary"):
            with st.spinner("生成中..."):
                pwd, entropy = generate_memorable_password(
                    num_words=num_words,
                    separator=separator,
                    capitalize=capitalize,
                    add_number=add_number
                )
                
                st.code(pwd, language=None)
                
                col_g1, col_g2 = st.columns(2)
                with col_g1:
                    st.button("📋 复制", key="copy_mem")
                with col_g2:
                    if st.button("🔄 重新生成", key="regen_mem"):
                        st.rerun()
                
                st.write(f"**熵值**: {entropy:.1f} bits")
                st.info("💡 适合需要口头告诉同事或记忆的场景")


# ========== Tab 3: 安全指南 ==========
with tab3:
    st.header("📖 密码安全最佳实践")
    
    with st.expander("🔐 核心原则", expanded=True):
        st.markdown("""
        1. **长度胜过复杂度**  
           16位以上的随机密码比8位复杂密码更安全。每增加1位，破解难度指数级增长。
        
        2. **每个账户唯一**  
           绝不重复使用密码。一次泄露可能导致所有账户被接管。使用密码管理器生成和保存唯一密码。
        
        3. **启用双因素认证(2FA)**  
           即使密码泄露，第二因素（如手机验证码、硬件密钥）仍能保护账户。
        
        4. **定期检查泄露**  
           使用 [Have I Been Pwned](https://haveibeenpwned.com) 等服务检查邮箱和密码是否出现在泄露事件中。
        """)
    
    with st.expander("🛡️ 密码管理工具推荐"):
        st.markdown("""
        | 工具 | 类型 | 特点 |
        |------|------|------|
        | **Bitwarden** | 密码管理器 | 开源免费，跨平台，支持自托管 |
        | **1Password** | 密码管理器 | 商业软件，用户体验优秀 |
        | **KeePassXC** | 密码管理器 | 完全离线，高度可控 |
        | **YubiKey** | 硬件密钥 | 物理2FA，最高安全性 |
        """)
    
    with st.expander("❓ 常见问题"):
        st.markdown("""
        **Q: 本工具会保存我的密码吗？**  
        A: 不会。密码仅在处理您的请求时短暂存在于服务端内存中，响应后立即释放，不做任何持久化存储。
        
        **Q: 为什么需要输入真实密码？**  
        A: 只有真实密码才能准确评估强度和检测泄露。建议在私密网络环境下使用，避免在公共WiFi下操作。
        
        **Q: 评估结果中的"熵值"是什么意思？**  
        A: 熵值衡量密码的不可预测性，单位为bits。熵值越高，密码越难被暴力破解。一般建议>45 bits。
        
        **Q: 如果密码显示已泄露，我该怎么办？**  
        A: 立即在所有使用该密码的网站上更换密码，不要仅做简单修改（如加数字）。建议使用密码生成器创建全新密码。
        """)


# ========== 底部信息 ==========
st.divider()
st.caption("""
<div style="text-align: center; color: #888;">
数据来源: <a href="https://haveibeenpwned.com" target="_blank">Have I Been Pwned</a> | 
AI分析由智谱GLM-4提供 | 
使用k-匿名技术保护您的隐私 | 
<a href="#" target="_blank">隐私政策</a>
</div>
""", unsafe_allow_html=True)