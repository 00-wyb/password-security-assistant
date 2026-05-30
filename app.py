"""
智能密码安全助手 - Day 6 修复版

修复：
- Streamlit widget session_state 修改限制（彻底移除对widget key的赋值）
- 跨标签页密码传递（使用session state标志位 + value参数）
- UI响应式适配
"""

import streamlit as st
from hibp_client import check_pwned
from password_evaluator import evaluate_password
from ai_client import AIClient
from password_generator import (
    generate_random_password, 
    generate_passphrase, 
    generate_memorable_password
)
from security_utils import safe_html, sanitize_input, validate_password_input


# ========== 页面配置 ==========
st.set_page_config(
    page_title="智能密码安全助手",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)


# ========== 初始化Session State ==========
if 'clear_input_flag' not in st.session_state:
    st.session_state['clear_input_flag'] = False
if 'generated_password' not in st.session_state:
    st.session_state['generated_password'] = ""
if 'gen_length' not in st.session_state:
    st.session_state['gen_length'] = 16


# ========== 初始化AI客户端 ==========
@st.cache_resource
def get_ai_client():
    try:
        api_key = st.secrets["ZHIPU_API_KEY"]
        base_url = st.secrets.get("AI_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
        return AIClient(api_key, base_url)
    except Exception:
        return None


ai_client = get_ai_client()


# ========== 全局CSS样式 ==========
st.markdown("""
<style>
    .security-banner {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 2rem;
        font-size: 0.9rem;
    }
    .score-big { font-size: 3rem; font-weight: bold; text-align: center; }
    .score-label { font-size: 1.2rem; font-weight: 600; text-align: center; }
    .leak-warning {
        background-color: #fee2e2;
        border-left: 4px solid #ef4444;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .leak-safe {
        background-color: #d1fae5;
        border-left: 4px solid #10b981;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .ai-card-risk {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .ai-card-advice {
        background-color: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .ai-card-tips {
        background-color: #eff6ff;
        border: 1px solid #bfdbfe;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .footer {
        text-align: center;
        color: #888;
        font-size: 0.8rem;
        margin-top: 2rem;
    }
    @media (max-width: 768px) {
        .score-big { font-size: 2rem; }
        .score-label { font-size: 1rem; }
    }
</style>
""", unsafe_allow_html=True)


# ========== 安全提示横幅 ==========
st.markdown("""
<div class="security-banner">
    🔒 <b>零登录 · 零持久化 · 隐私优先</b><br>
    密码仅在服务端内存中处理，响应后立即销毁，不做任何存储
</div>
""", unsafe_allow_html=True)


# ========== 主标题 ==========
st.markdown("<h1 style='text-align: center; margin-bottom: 0;'>🔐 智能密码安全助手</h1>", 
            unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #666; margin-top: 0.5rem;'>"
            "基于AI增强的密码安全检测工具</p>", 
            unsafe_allow_html=True)


# ========== 标签页导航 ==========
tab1, tab2, tab3 = st.tabs(["🔍 评估密码", "🔑 生成密码", "📖 安全指南"])


# ============================================================
# Tab 1: 密码评估
# ============================================================
with tab1:
    st.header("🔍 密码强度评估")
    
    # 确定输入框的初始值（从生成页传递或清空）
    if st.session_state['clear_input_flag']:
        input_value = ""
        st.session_state['clear_input_flag'] = False
    elif st.session_state['generated_password']:
        input_value = st.session_state['generated_password']
        st.session_state['generated_password'] = ""  # 使用后清空
    else:
        input_value = ""
    
    # 密码输入框（无key，使用value控制初始值）
    password_input = st.text_input(
        label="输入要评估的密码",
        type="password",
        value=input_value,
        placeholder="输入或粘贴要检测的密码...",
        label_visibility="collapsed",
        help="密码将被安全处理，不会被保存（最大128字符）",
        max_chars=128
        # 注意：没有 key 参数！
    )
    
    # 清理输入
    password = sanitize_input(password_input, max_length=128)
    
    # 选项
    col_opt1, col_opt2 = st.columns([1, 2])
    with col_opt1:
        check_leak = st.checkbox("检测泄露", value=True, 
                                help="联网查询Have I Been Pwned数据库")
    with col_opt2:
        st.caption("💡 建议同时检测泄露以获得完整安全报告")
    
    # 操作按钮
    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        evaluate_btn = st.button("📊 开始评估", type="primary", use_container_width=True)
    with btn_col2:
        # 清除按钮：设置标志位，下次渲染时清空输入框
        if st.button("🧹 清除结果", use_container_width=True):
            # 删除结果数据
            for key in ['last_password', 'eval_result']:
                if key in st.session_state:
                    del st.session_state[key]
            # 设置清空标志（下次渲染时生效）
            st.session_state['clear_input_flag'] = True
            st.rerun()
    
    # 执行评估
    if evaluate_btn and password:
        is_valid, error_msg = validate_password_input(password)
        if not is_valid:
            st.error(f"❌ {error_msg}")
        else:
            with st.spinner("正在分析密码安全性..."):
                # 保存用于生成器跳转
                st.session_state['last_password'] = password
                
                # 1. 规则引擎评估
                eval_result = evaluate_password(password)
                
                # 2. HIBP泄露查询
                is_pwned = False
                pwned_count = 0
                if check_leak:
                    is_pwned, pwned_count = check_pwned(password)
                
                # ========== 泄露状态 ==========
                st.divider()
                
                if check_leak:
                    if pwned_count == -1:
                        st.warning("⚠️ 泄露查询失败 - HIBP服务暂时不可用")
                    elif is_pwned:
                        st.markdown(f"""
                        <div class="leak-warning">
                            <h3 style="color: #dc2626; margin-top: 0;">🚨 紧急警告</h3>
                            <p style="font-size: 1.2rem; margin-bottom: 0.5rem;">
                                该密码已在数据泄露中出现 <b>{pwned_count:,}</b> 次！
                            </p>
                            <p style="margin-bottom: 0;">请立即在所有使用该密码的网站上更换密码</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="leak-safe">
                            <h4 style="color: #059669; margin-top: 0;">✅ 未泄露</h4>
                            <p style="margin-bottom: 0;">该密码未在已知泄露数据库中发现</p>
                        </div>
                        """, unsafe_allow_html=True)
                
                # ========== 综合评分 ==========
                score_col, info_col = st.columns([1, 2])
                
                with score_col:
                    score_color = eval_result['color']
                    st.markdown(f"""
                    <div style="text-align: center; padding: 1rem;">
                        <div class="score-big" style="color: {score_color};">
                            {eval_result['score']}
                        </div>
                        <div class="score-label" style="color: {score_color};">
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
                
                # ========== 维度拆解 ==========
                st.subheader("📊 维度拆解")
                
                dim_cols = st.columns(4)
                with dim_cols[0]:
                    st.metric("长度", f"{eval_result['length_score']}/40",
                             delta="✓" if eval_result['length_score'] >= 15 else "✗")
                with dim_cols[1]:
                    st.metric("复杂度", f"{eval_result['complexity_score']}/30",
                             delta="✓" if eval_result['complexity_score'] >= 21 else "✗")
                with dim_cols[2]:
                    st.metric("模式安全", f"{eval_result['pattern_score']}/30",
                             delta="✓" if eval_result['pattern_score'] >= 20 else "✗")
                with dim_cols[3]:
                    st.metric("熵值", f"{eval_result['entropy_score']}/25",
                             delta="✓" if eval_result['entropy_score'] >= 10 else "✗")
                
                # 风险模式警告
                if eval_result['patterns_found']:
                    st.warning(f"⚠️ 检测到风险模式: {', '.join(eval_result['patterns_found'])}")
                
                # ========== AI分析 ==========
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
                    st.info("💡 AI服务未配置，显示预设建议")
                
                st.markdown(f"""
                <div class="ai-card-risk">
                    <h4 style="color: #475569; margin-top: 0;">🔍 风险解释</h4>
                    <p style="color: #334155; line-height: 1.6;">
                        {safe_html(ai_result['risk_explanation'])}
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"""
                <div class="ai-card-advice">
                    <h4 style="color: #166534; margin-top: 0;">💡 改进建议</h4>
                    <p style="color: #14532d; line-height: 1.6;">
                        {safe_html(ai_result['improvement_advice'])}
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"""
                <div class="ai-card-tips">
                    <h4 style="color: #1e40af; margin-top: 0;">📚 安全小贴士</h4>
                    <p style="color: #1e3a8a; line-height: 1.6;">
                        {safe_html(ai_result['security_tips'])}
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                # ========== 改进清单 ==========
                st.divider()
                st.subheader("📋 快速改进清单")
                for i, suggestion in enumerate(eval_result['suggestions'], 1):
                    st.write(f"{i}. {safe_html(suggestion)}")
                
                # 生成替代密码按钮
                if st.button("🔑 生成替代密码", type="secondary"):
                    st.session_state['gen_length'] = max(16, eval_result['length'])
                    st.info("请切换到「生成密码」标签页生成强密码")
                
                st.caption("🔒 本次分析已完成，密码已从内存中清除")


# ============================================================
# Tab 2: 密码生成器
# ============================================================
with tab2:
    st.header("🔑 智能密码生成器")
    
    # 生成模式选择
    gen_mode = st.radio(
        "选择生成模式",
        ["🎲 随机密码（最安全）", "📝 口令密码（易记）", "💭 易记密码（单词组合）"],
        horizontal=True,
        key="gen_mode"
    )
    
    # ========== 模式1：随机密码 ==========
    if gen_mode == "🎲 随机密码（最安全）":
        st.subheader("配置参数")
        
        col1, col2 = st.columns(2)
        with col1:
            gen_length = st.slider("密码长度", 8, 32, 
                                  st.session_state.get('gen_length', 16), 
                                  key="random_length")
        with col2:
            target_strength = st.selectbox(
                "目标强度", ["强（推荐）", "极强"], index=0, key="random_strength"
            )
        
        st.write("**字符类型**:")
        ct_col1, ct_col2, ct_col3, ct_col4 = st.columns(4)
        with ct_col1: use_lower = st.checkbox("小写字母", True, key="r_lower")
        with ct_col2: use_upper = st.checkbox("大写字母", True, key="r_upper")
        with ct_col3: use_digit = st.checkbox("数字", True, key="r_digit")
        with ct_col4: use_symbol = st.checkbox("符号", True, key="r_symbol")
        
        st.write("**高级选项**:")
        exclude_ambig = st.checkbox("排除易混淆字符 (0/O/1/l/I)", True, key="r_ambig")
        
        if st.button("✨ 生成随机密码", type="primary"):
            if not any([use_lower, use_upper, use_digit, use_symbol]):
                st.error("请至少选择一种字符类型")
            else:
                with st.spinner("生成中..."):
                    if target_strength == "极强" and gen_length < 20:
                        gen_length = 20
                    
                    pwd, entropy = generate_random_password(
                        length=gen_length,
                        use_upper=use_upper,
                        use_lower=use_lower,
                        use_digit=use_digit,
                        use_symbol=use_symbol,
                        exclude_ambiguous=exclude_ambig
                    )
                    
                    eval_result = evaluate_password(pwd)
                    
                    st.divider()
                    st.code(pwd, language=None)
                    
                    # 复制和评估按钮
                    act_col1, act_col2 = st.columns(2)
                    with act_col1:
                        st.button("📋 复制到剪贴板", key="copy_rand")
                    with act_col2:
                        # 传递密码到评估页
                        if st.button("📊 去评估此密码", key="eval_rand"):
                            st.session_state['generated_password'] = pwd
                            st.info("密码已准备好，请切换到「评估密码」标签页查看")
                    
                    st.write(f"**安全评分**: {eval_result['score']}/100 "
                            f"({safe_html(eval_result['level'])})")
                    st.write(f"**估算熵值**: {entropy:.1f} bits")
                    
                    if entropy > 60:
                        crack_time = "> 10¹⁵ 年"
                    elif entropy > 45:
                        crack_time = "> 10⁹ 年"
                    elif entropy > 35:
                        crack_time = "数百年"
                    else:
                        crack_time = "数小时至数年"
                    
                    st.write(f"**预计破解时间**: {crack_time}")
                    
                    parts = []
                    if eval_result['has_lower']: parts.append("小写字母")
                    if eval_result['has_upper']: parts.append("大写字母")
                    if eval_result['has_digit']: parts.append("数字")
                    if eval_result['has_symbol']: parts.append("符号")
                    st.write(f"**包含**: {', '.join(parts)}")
                    
                    if exclude_ambig:
                        st.success("✓ 已排除易混淆字符")
    
    # ========== 模式2：口令密码 ==========
    elif gen_mode == "📝 口令密码（易记）":
        st.subheader("配置参数")
        
        col1, col2 = st.columns(2)
        with col1:
            num_words = st.slider("单词数量", 3, 6, 4, key="pp_words")
        with col2:
            separator = st.selectbox("分隔符", ["-", "_", ".", " "], index=0, key="pp_sep")
        
        add_num = st.checkbox("添加随机数字", True, key="pp_num")
        add_sym = st.checkbox("添加随机符号", True, key="pp_sym")
        
        if st.button("✨ 生成口令", type="primary"):
            with st.spinner("生成中..."):
                pwd, entropy = generate_passphrase(
                    num_words=num_words,
                    separator=separator,
                    include_number=add_num,
                    include_symbol=add_sym
                )
                
                st.divider()
                st.code(pwd, language=None)
                
                act_col1, act_col2 = st.columns(2)
                with act_col1:
                    st.button("📋 复制", key="copy_pp")
                with act_col2:
                    if st.button("📊 去评估此密码", key="eval_pp"):
                        st.session_state['generated_password'] = pwd
                        st.info("密码已准备好，请切换到「评估密码」标签页查看")
                
                st.write(f"**估算熵值**: {entropy:.1f} bits")
                st.info("💡 口令密码由常见单词组成，易于记忆")
    
    # ========== 模式3：易记密码 ==========
    else:
        st.subheader("配置参数")
        
        col1, col2 = st.columns(2)
        with col1:
            mem_words = st.slider("单词数量", 2, 4, 3, key="mem_words")
        with col2:
            mem_sep = st.selectbox("分隔符", ["-", "_", "."], index=0, key="mem_sep")
        
        mem_cap = st.checkbox("随机大写", True, key="mem_cap")
        mem_num = st.checkbox("添加数字后缀", True, key="mem_num")
        
        if st.button("✨ 生成易记密码", type="primary"):
            with st.spinner("生成中..."):
                pwd, entropy = generate_memorable_password(
                    num_words=mem_words,
                    separator=mem_sep,
                    capitalize=mem_cap,
                    add_number=mem_num
                )
                
                st.divider()
                st.code(pwd, language=None)
                
                act_col1, act_col2 = st.columns(2)
                with act_col1:
                    st.button("📋 复制", key="copy_mem")
                with act_col2:
                    if st.button("📊 去评估此密码", key="eval_mem"):
                        st.session_state['generated_password'] = pwd
                        st.info("密码已准备好，请切换到「评估密码」标签页查看")
                
                st.write(f"**估算熵值**: {entropy:.1f} bits")
                st.info("💡 适合需要口头告诉同事的场景")


# ============================================================
# Tab 3: 安全指南
# ============================================================
with tab3:
    st.header("📖 密码安全最佳实践")
    
    # 核心原则
    with st.expander("🔐 核心原则", expanded=True):
        st.markdown("""
        ### 1. 长度胜过复杂度
        **16位以上的随机密码**比8位复杂密码更安全。
        
        | 长度 | 组合数 | 破解时间 |
        |-----|--------|---------|
        | 8位 | 6.6×10¹⁵ | 数小时 |
        | 12位 | 4.7×10²³ | 数千年 |
        | 16位 | 3.3×10³¹ | 数亿年 |
        
        ### 2. 每个账户唯一
        绝不重复使用密码。使用密码管理器（Bitwarden、1Password）。
        
        ### 3. 启用双因素认证 (2FA)
        硬件密钥 (YubiKey) > 认证器App > 短信验证码
        
        ### 4. 定期检查泄露
        使用 [Have I Been Pwned](https://haveibeenpwned.com) 检查。
        """)
    
    # 工具推荐
    with st.expander("🛡️ 推荐工具"):
        st.markdown("""
        | 工具 | 类型 | 特点 |
        |-----|------|------|
        | Bitwarden | 密码管理器 | 开源免费，跨平台 |
        | 1Password | 密码管理器 | 商业软件，体验优秀 |
        | KeePassXC | 密码管理器 | 完全离线 |
        | YubiKey | 硬件密钥 | 最高安全性 |
        """)
    
    # 常见问题
    with st.expander("❓ 常见问题"):
        st.markdown("""
        **Q: 本工具会保存我的密码吗？**  
        A: **不会。** 密码仅在处理请求时短暂存在于服务端内存中，响应后立即释放。
        
        **Q: 为什么需要输入真实密码？**  
        A: 只有真实密码才能准确评估强度和检测泄露。建议在私密网络环境下使用。
        
        **Q: 如果密码显示已泄露，我该怎么办？**  
        A: 立即在所有使用该密码的网站上更换，不要仅做简单修改。
        """)
    
    # 关于
    with st.expander("ℹ️ 关于本工具"):
        st.markdown("""
        ### 技术架构
        - **前端**: Streamlit (Python)
        - **AI**: 智谱GLM-4（脱敏特征分析）
        - **泄露数据库**: Have I Been Pwned（k-匿名查询）
        - **部署**: Streamlit Cloud
        
        ### 安全承诺
        - ✅ 零登录：无需注册，打开即用
        - ✅ 零持久化：不保存任何数据到磁盘
        - ✅ 即时销毁：响应后立即释放内存
        """)


# ========== 页脚 ==========
st.markdown("""
<div class="footer">
    <hr style="margin: 2rem 0 1rem 0;">
    <p>
        🔒 零登录 · 零持久化 · 开源可审计 | 
        数据来源: <a href="https://haveibeenpwned.com" target="_blank">Have I Been Pwned</a> | 
        AI分析: 智谱GLM-4
    </p>
    <p style="font-size: 0.75rem; color: #aaa;">
        密码仅在请求处理期间存在于服务端内存中，响应后立即销毁
    </p>
</div>
""", unsafe_allow_html=True)