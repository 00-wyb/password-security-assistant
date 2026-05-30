"""
智能密码安全助手 - Day 5 版本

功能：密码泄露查询 + 密码强度评估 + AI智能分析 + 密码生成器
架构：隐私优先（零登录、零持久化、即时销毁）
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


# ========== 初始化AI客户端 ==========
@st.cache_resource
def get_ai_client():
    """缓存AI客户端，避免重复初始化"""
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
    /* 安全横幅 */
    .security-banner {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 2rem;
        font-size: 0.9rem;
    }
    /* 评分大数字 */
    .score-big {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
    }
    .score-label {
        font-size: 1.2rem;
        font-weight: 600;
        text-align: center;
    }
    /* 泄露警告卡片 */
    .leak-warning {
        background-color: #fee2e2;
        border-left: 4px solid #ef4444;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    /* 泄露安全卡片 */
    .leak-safe {
        background-color: #d1fae5;
        border-left: 4px solid #10b981;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    /* AI分析卡片 */
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
    /* 页脚 */
    .footer {
        text-align: center;
        color: #888;
        font-size: 0.8rem;
        margin-top: 2rem;
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
    
    # 密码输入框
    password_input = st.text_input(
        label="输入要评估的密码",
        type="password",
        placeholder="输入或粘贴要检测的密码...",
        label_visibility="collapsed",
        help="密码将被安全处理，不会被保存（最大128字符）",
        max_chars=128,
        key="eval_input"
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
    btn_col1, btn_col2, btn_col3 = st.columns([2, 2, 3])
    with btn_col1:
        evaluate_btn = st.button("📊 开始评估", type="primary", use_container_width=True)
    with btn_col2:
        # 清除按钮
        if st.button("🧹 清除数据", use_container_width=True):
            # 删除所有非 widget 的 session state
            keys_to_clear = [k for k in st.session_state.keys()  if k not in ['eval_input']]
            for key in keys_to_clear:
                del st.session_state[key]
            st.rerun()
    
    # 执行评估
    if evaluate_btn and password:
        # 输入验证
        is_valid, error_msg = validate_password_input(password)
        if not is_valid:
            st.error(f"❌ {error_msg}")
        else:
            with st.spinner("正在分析密码安全性..."):
                # 保存到session（用于生成器跳转）
                st.session_state['last_password'] = password
                
                # 1. 规则引擎评估
                eval_result = evaluate_password(password)
                
                # 2. HIBP泄露查询（如果勾选）
                is_pwned = False
                pwned_count = 0
                if check_leak:
                    is_pwned, pwned_count = check_pwned(password)
                
                # ========== 评分展示区域 ==========
                st.divider()
                
                # 泄露状态优先显示（最高优先级）
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
                
                # 综合评分
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
                    # 降级模式
                    ai_result = AIClient("dummy")._fallback_response(
                        eval_result['score'], is_pwned, eval_result['level']
                    )
                    st.info("💡 AI服务未配置，显示预设建议")
                
                # 使用safe_html防止XSS
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
                
                # ========== 快速改进清单 ==========
                st.divider()
                st.subheader("📋 快速改进清单")
                for i, suggestion in enumerate(eval_result['suggestions'], 1):
                    st.write(f"{i}. {safe_html(suggestion)}")
                
                # 生成替代密码按钮
                if st.button("🔑 生成替代密码", type="secondary"):
                    st.session_state['gen_length'] = max(16, eval_result['length'])
                    st.session_state['switch_tab'] = 'generate'
                    st.info("请切换到「生成密码」标签页查看生成的强密码")
                
                # 隐私声明
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
                "目标强度", 
                ["强（推荐）", "极强"], 
                index=0,
                key="random_strength"
            )
        
        # 字符类型
        st.write("**字符类型**:")
        ct_col1, ct_col2, ct_col3, ct_col4 = st.columns(4)
        with ct_col1: use_lower = st.checkbox("小写字母", True, key="r_lower")
        with ct_col2: use_upper = st.checkbox("大写字母", True, key="r_upper")
        with ct_col3: use_digit = st.checkbox("数字", True, key="r_digit")
        with ct_col4: use_symbol = st.checkbox("符号", True, key="r_symbol")
        
        # 高级选项
        st.write("**高级选项**:")
        exclude_ambig = st.checkbox("排除易混淆字符 (0/O/1/l/I)", True, key="r_ambig")
        
        # 生成按钮
        if st.button("✨ 生成随机密码", type="primary"):
            # 验证至少选择一种字符类型
            if not any([use_lower, use_upper, use_digit, use_symbol]):
                st.error("请至少选择一种字符类型")
            else:
                with st.spinner("生成中..."):
                    # 根据目标强度调整长度
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
                    
                    # 自动评估生成的密码
                    eval_result = evaluate_password(pwd)
                    
                    # 显示结果
                    st.divider()
                    st.code(pwd, language=None)
                    
                    # 操作按钮
                    act_col1, act_col2, act_col3 = st.columns(3)
                    with act_col1:
                        st.button("📋 复制", key="copy_rand", 
                                 help="点击复制到剪贴板")
                    with act_col2:
                        if st.button("🔄 重新生成", key="regen_rand"):
                            st.rerun()
                    with act_col3:
                        if st.button("📊 评估此密码", key="eval_rand"):
                            st.session_state['eval_input'] = pwd
                            st.info("请切换到「评估密码」标签页查看详细分析")
                    
                    # 评估信息
                    st.write(f"**安全评分**: {eval_result['score']}/100 "
                            f"({safe_html(eval_result['level'])})")
                    st.write(f"**估算熵值**: {entropy:.1f} bits")
                    
                    # 破解时间估算
                    if entropy > 60:
                        crack_time = "> 10¹⁵ 年（几乎不可能破解）"
                    elif entropy > 45:
                        crack_time = "> 10⁹ 年（当前技术不可行）"
                    elif entropy > 35:
                        crack_time = "数百年（需要超级计算机）"
                    else:
                        crack_time = "数小时至数年（建议使用更长密码）"
                    
                    st.write(f"**预计破解时间**: {crack_time}")
                    
                    # 构成解析
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
            separator = st.selectbox("分隔符", ["-", "_", ".", " "], 
                                    index=0, key="pp_sep")
        
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
                    if st.button("🔄 重新生成", key="regen_pp"):
                        st.rerun()
                
                st.write(f"**估算熵值**: {entropy:.1f} bits")
                st.info("💡 口令密码由常见单词组成，易于记忆但安全性略低于完全随机密码")
                st.write("**适用场景**: 需要口头告诉他人、或不便使用密码管理器的场景")
    
    # ========== 模式3：易记密码 ==========
    else:  # 💭 易记密码
        st.subheader("配置参数")
        
        col1, col2 = st.columns(2)
        with col1:
            mem_words = st.slider("单词数量", 2, 4, 3, key="mem_words")
        with col2:
            mem_sep = st.selectbox("分隔符", ["-", "_", "."], 
                                  index=0, key="mem_sep")
        
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
                    if st.button("🔄 重新生成", key="regen_mem"):
                        st.rerun()
                
                st.write(f"**估算熵值**: {entropy:.1f} bits")
                st.info("💡 适合需要记忆但又比纯单词更安全的场景")


# ============================================================
# Tab 3: 安全指南
# ============================================================
with tab3:
    st.header("📖 密码安全最佳实践")
    
    # 个性化建议（基于评估历史）
    if 'last_score' in st.session_state:
        last_score = st.session_state['last_score']
        if last_score < 40:
            st.error("⚠️ 根据您上次的评估结果，您的密码安全性较弱，请重点阅读以下建议")
        elif last_score < 70:
            st.warning("⚡ 您的密码还有提升空间，建议启用双因素认证")
        else:
            st.success("✅ 您的密码安全性良好，继续保持！")
    
    # 核心原则
    with st.expander("🔐 核心原则", expanded=True):
        st.markdown("""
        ### 1. 长度胜过复杂度
        **16位以上的随机密码**比8位复杂密码更安全。每增加1位，破解难度翻倍。
        
        | 密码长度 | 可能的组合数 | 破解时间估算 |
        |---------|------------|------------|
        | 8位 | 6.6 × 10¹⁵ | 数小时 |
        | 12位 | 4.7 × 10²³ | 数千年 |
        | 16位 | 3.3 × 10³¹ | 数亿年 |
        | 20位 | 2.4 × 10³⁹ | 不可破解 |
        
        ### 2. 每个账户唯一
        绝不重复使用密码。一次泄露可能导致**所有账户被接管**。
        
        > 💡 使用密码管理器（如 Bitwarden、1Password）自动生成和保存唯一密码。
        
        ### 3. 启用双因素认证 (2FA)
        即使密码泄露，第二因素（手机验证码、硬件密钥）仍能保护账户。
        
        **2FA优先级**: 硬件密钥 (YubiKey) > 认证器App (Authy) > 短信验证码
        
        ### 4. 定期检查泄露
        使用 [Have I Been Pwned](https://haveibeenpwned.com) 检查您的邮箱和密码是否出现在泄露事件中。
        """)
    
    # 工具推荐
    with st.expander("🛡️ 推荐工具"):
        st.markdown("""
        | 工具 | 类型 | 特点 | 适用场景 |
        |-----|------|------|---------|
        | **Bitwarden** | 密码管理器 | 开源免费，跨平台，支持自托管 | 日常密码管理 |
        | **1Password** | 密码管理器 | 商业软件，用户体验优秀 | 团队/企业使用 |
        | **KeePassXC** | 密码管理器 | 完全离线，高度可控 | 高安全需求用户 |
        | **YubiKey** | 硬件密钥 | 物理2FA，最高安全性 | 重要账户保护 |
        | **Authy** | 2FA应用 | 云端备份，多设备同步 | 替代Google Authenticator |
        """)
    
    # 常见问题
    with st.expander("❓ 常见问题"):
        st.markdown("""
        **Q: 本工具会保存我的密码吗？**  
        A: **不会。** 密码仅在处理您的请求时短暂存在于服务端内存中，响应后立即释放，不做任何持久化存储（不写入磁盘、数据库或日志）。
        
        **Q: 为什么需要输入真实密码？**  
        A: 只有真实密码才能准确评估强度和检测泄露。建议在**私密网络环境**下使用，避免在公共WiFi下操作。
        
        **Q: "已泄露"是什么意思？**  
        A: 表示该密码曾在已知的数据泄露事件中出现（如某网站被黑客攻击）。**即使您没有直接受影响**，如果该密码与其他账户相同，那些账户也面临风险。
        
        **Q: 如果密码显示已泄露，我该怎么办？**  
        A: 
        1. **立即**在所有使用该密码的网站上更换密码
        2. **不要**仅做简单修改（如加数字、改大小写）
        3. 使用密码生成器创建**全新的、唯一的**强密码
        4. 检查其他账户是否使用了相同密码
        
        **Q: 什么是"熵值"？**  
        A: 熵值衡量密码的不可预测性，单位为 bits。熵值越高，密码越难被暴力破解：
        - < 28 bits: 极弱（瞬间破解）
        - 28-35 bits: 弱（数分钟）
        - 35-45 bits: 中等（数小时至数天）
        - 45-60 bits: 强（数年）
        - > 60 bits: 极强（不可破解）
        """)
    
    # 关于本工具
    with st.expander("ℹ️ 关于本工具"):
        st.markdown("""
        ### 技术架构
        - **前端框架**: Streamlit（Python）
        - **AI服务**: 智谱GLM-4（脱敏特征分析）
        - **泄露数据库**: Have I Been Pwned（k-匿名查询）
        - **部署平台**: Streamlit Cloud
        
        ### 安全承诺
        - ✅ 零登录：无需注册，打开即用
        - ✅ 零持久化：不保存任何数据到磁盘
        - ✅ 即时销毁：响应后立即释放内存
        - ✅ 透明可信：代码开源可审计
        
        ### 隐私保护技术
        - **k-匿名协议**: 查询泄露时仅传输密码哈希的前5位，保护原始密码
        - **特征脱敏**: AI分析仅传输评分、长度等统计信息，不包含密码内容
        - **HTTPS加密**: 所有数据传输均使用TLS 1.3加密
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
        密码仅在请求处理期间存在于服务端内存中，响应后立即销毁 | 
        <a href="#" target="_blank">隐私政策</a> | 
        <a href="#" target="_blank">服务条款</a>
    </p>
</div>
""", unsafe_allow_html=True)