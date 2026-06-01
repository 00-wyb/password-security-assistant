"""
智能密码安全助手 - 修复版
修复内容：
1. 替代密码模块：使用Pending Action模式，解决延迟显示问题
2. 生成器重新生成：使用Pending Action模式，解决点击无效问题
3. 简化替代密码显示：移除多余密码框
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


# ========== 状态机定义 ==========
class AppState:
    """应用状态机 - 单一数据源"""
    
    # 页面标识
    PAGE_EVAL = "eval"
    PAGE_GEN = "gen"
    PAGE_GUIDE = "guide"
    
    # 生成模式
    MODE_RANDOM = 0
    MODE_PASSPHRASE = 1
    MODE_MEMORABLE = 2
    
    @staticmethod
    def init():
        """初始化所有状态"""
        defaults = {
            # 当前页面
            'current_page': AppState.PAGE_EVAL,
            
            # 评估页状态
            'eval_input': "",
            'eval_result_cache': None,
            'eval_leak_checked': True,
            'show_eval_result': False,
            
            # 生成页状态
            'gen_mode': AppState.MODE_RANDOM,
            'gen_result_cache': None,
            'show_gen_result': False,
            
            # 生成参数 - 随机密码
            'rand_length': 16,
            'rand_upper': True,
            'rand_lower': True,
            'rand_digit': True,
            'rand_symbol': True,
            'rand_ambig': True,
            
            # 生成参数 - 口令
            'pp_words': 4,
            'pp_sep': "-",
            'pp_num': True,
            'pp_sym': True,
            
            # 生成参数 - 易记
            'mem_words': 3,
            'mem_sep': "-",
            'mem_cap': True,
            'mem_num': True,
            
            # 自然语言描述
            'user_desc': "",
            
            # ===== 修复：替代密码使用Pending Action机制 =====
            'alt_password': "",
            'alt_eval': None,
            'alt_entropy': 0,
            # 不再使用show_alt_password，改为pending机制
            
            # ===== 修复：增加替代密码的Pending Action =====
            'pending_alt_gen': False,
            'pending_alt_length': 16,
            
            # 待处理操作
            'pending_action': None,
            'pending_password': "",
            'pending_gen_params': None,
            
            # ===== 修复：增加生成器重新生成的Pending Action =====
            'pending_regen': False,
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value
    
    @staticmethod
    def get(key, default=None):
        return st.session_state.get(key, default)
    
    @staticmethod
    def set(key, value):
        st.session_state[key] = value
    
    @staticmethod
    def clear_eval():
        """清除评估状态"""
        st.session_state['eval_input'] = ""
        st.session_state['eval_result_cache'] = None
        st.session_state['show_eval_result'] = False
        st.session_state['alt_password'] = ""
        st.session_state['alt_eval'] = None
        st.session_state['alt_entropy'] = 0
        st.session_state['pending_alt_gen'] = False
    
    @staticmethod
    def clear_gen():
        """清除生成状态"""
        st.session_state['gen_result_cache'] = None
        st.session_state['show_gen_result'] = False
        st.session_state['pending_regen'] = False


# 初始化状态机
AppState.init()


# ========== 处理待执行操作（在创建widget之前）==========

pending = AppState.get('pending_action')

if pending == "eval_password":
    pwd = AppState.get('pending_password')
    if pwd:
        eval_result = evaluate_password(pwd)
        leak_checked = AppState.get('eval_leak_checked')
        is_pwned = False
        pwned_count = 0
        
        if leak_checked:
            is_pwned, pwned_count = check_pwned(pwd)
        
        AppState.set('eval_result_cache', {
            'password': pwd,
            'eval_result': eval_result,
            'is_pwned': is_pwned,
            'pwned_count': pwned_count,
            'leak_checked': leak_checked,
        })
        AppState.set('show_eval_result', True)
        AppState.set('eval_input', pwd)
    
    AppState.set('pending_action', None)
    AppState.set('pending_password', "")

elif pending == "gen_password":
    params = AppState.get('pending_gen_params')
    if params:
        mode = params['mode']
        
        if mode == AppState.MODE_RANDOM:
            pwd, entropy = generate_random_password(
                length=params['length'],
                use_upper=params['upper'],
                use_lower=params['lower'],
                use_digit=params['digit'],
                use_symbol=params['symbol'],
                exclude_ambiguous=params['ambig']
            )
        elif mode == AppState.MODE_PASSPHRASE:
            pwd, entropy = generate_passphrase(
                num_words=params['words'],
                separator=params['sep'],
                include_number=params['num'],
                include_symbol=params['sym']
            )
        else:
            pwd, entropy = generate_memorable_password(
                num_words=params['words'],
                separator=params['sep'],
                capitalize=params['cap'],
                add_number=params['num']
            )
        
        AppState.set('gen_result_cache', {
            'password': pwd,
            'entropy': entropy,
            'eval': evaluate_password(pwd),
            'mode': mode,
        })
        AppState.set('show_gen_result', True)
        AppState.set('gen_mode', mode)
    
    AppState.set('pending_action', None)
    AppState.set('pending_gen_params', None)

elif pending == "clear_eval":
    AppState.clear_eval()
    AppState.set('pending_action', None)


# ===== 修复：处理替代密码的Pending Action =====
if AppState.get('pending_alt_gen'):
    length = AppState.get('pending_alt_length')
    pwd, entropy = generate_random_password(
        length=max(16, length),
        use_upper=True, use_lower=True, use_digit=True, use_symbol=True,
        exclude_ambiguous=True
    )
    AppState.set('alt_password', pwd)
    AppState.set('alt_eval', evaluate_password(pwd))
    AppState.set('alt_entropy', entropy)
    AppState.set('pending_alt_gen', False)


# ===== 修复：处理生成器重新生成的Pending Action =====
if AppState.get('pending_regen'):
    # 获取当前UI参数
    selected_mode = AppState.get('gen_mode')
    
    if selected_mode == AppState.MODE_RANDOM:
        params = {
            'mode': AppState.MODE_RANDOM,
            'length': AppState.get('rand_length'),
            'lower': AppState.get('rand_lower'),
            'upper': AppState.get('rand_upper'),
            'digit': AppState.get('rand_digit'),
            'symbol': AppState.get('rand_symbol'),
            'ambig': AppState.get('rand_ambig'),
        }
        pwd, entropy = generate_random_password(
            length=params['length'],
            use_lower=params['lower'],
            use_upper=params['upper'],
            use_digit=params['digit'],
            use_symbol=params['symbol'],
            exclude_ambiguous=params['ambig']
        )
    elif selected_mode == AppState.MODE_PASSPHRASE:
        params = {
            'mode': AppState.MODE_PASSPHRASE,
            'words': AppState.get('pp_words'),
            'sep': AppState.get('pp_sep'),
            'num': AppState.get('pp_num'),
            'sym': AppState.get('pp_sym'),
        }
        pwd, entropy = generate_passphrase(
            num_words=params['words'],
            separator=params['sep'],
            include_number=params['num'],
            include_symbol=params['sym']
        )
    else:
        params = {
            'mode': AppState.MODE_MEMORABLE,
            'words': AppState.get('mem_words'),
            'sep': AppState.get('mem_sep'),
            'cap': AppState.get('mem_cap'),
            'num': AppState.get('mem_num'),
        }
        pwd, entropy = generate_memorable_password(
            num_words=params['words'],
            separator=params['sep'],
            capitalize=params['cap'],
            add_number=params['num']
        )
    
    AppState.set('gen_result_cache', {
        'password': pwd,
        'entropy': entropy,
        'eval': evaluate_password(pwd),
        'mode': selected_mode,
    })
    AppState.set('pending_regen', False)


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


# ========== CSS样式 ==========
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
    .leak-unchecked {
        background-color: #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .pwd-box {
        background-color: #1e293b;
        color: #e2e8f0;
        padding: 1.5rem;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        font-size: 1.3rem;
        text-align: center;
        margin: 1rem 0;
        letter-spacing: 2px;
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
    .evaluated-pwd {
        background-color: #f1f5f9;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        font-family: monospace;
        margin: 0.5rem 0;
    }
    @media (max-width: 768px) {
        .score-big { font-size: 2rem; }
        .score-label { font-size: 1rem; }
    }
    /* ===== 修复：替代密码区域样式优化 ===== */
    .alt-password-section {
        background-color: #f8fafc;
        border: 2px solid #e2e8f0;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    .alt-password-code {
        background-color: #1e293b;
        color: #e2e8f0;
        padding: 1rem;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        font-size: 1.2rem;
        text-align: center;
        margin: 0.5rem 0;
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


# ========== 页面切换按钮 ==========
col_nav1, col_nav2, col_nav3 = st.columns(3)

with col_nav1:
    eval_active = AppState.get('current_page') == AppState.PAGE_EVAL
    if st.button("🔍 评估密码", type="primary" if eval_active else "secondary", 
                 use_container_width=True, key="nav_eval"):
        AppState.set('current_page', AppState.PAGE_EVAL)
        st.rerun()

with col_nav2:
    gen_active = AppState.get('current_page') == AppState.PAGE_GEN
    if st.button("🔑 生成密码", type="primary" if gen_active else "secondary",
                 use_container_width=True, key="nav_gen"):
        AppState.set('current_page', AppState.PAGE_GEN)
        st.rerun()

with col_nav3:
    guide_active = AppState.get('current_page') == AppState.PAGE_GUIDE
    if st.button("📖 安全指南", type="primary" if guide_active else "secondary",
                 use_container_width=True, key="nav_guide"):
        AppState.set('current_page', AppState.PAGE_GUIDE)
        st.rerun()

st.divider()


# ============================================================
# 页面：评估密码
# ============================================================
if AppState.get('current_page') == AppState.PAGE_EVAL:
    st.header("🔍 密码强度评估")
    
    # 密码输入
    current_input = AppState.get('eval_input')
    
    password_raw = st.text_input(
        label="输入要评估的密码",
        type="password",
        value=current_input,
        key="eval_input_widget",
        placeholder="输入或粘贴要检测的密码...",
        label_visibility="collapsed",
        help="密码将被安全处理，不会被保存（最大128字符）",
        max_chars=128
    )
    
    # 同步widget值到状态机
    AppState.set('eval_input', password_raw)
    password = sanitize_input(password_raw, max_length=128)
    
    # 泄露检测选项
    col_opt1, col_opt2 = st.columns([1, 2])
    with col_opt1:
        leak_check = st.checkbox(
            "检测泄露", 
            value=AppState.get('eval_leak_checked'),
            key="leak_check_widget"
        )
        AppState.set('eval_leak_checked', leak_check)
    with col_opt2:
        st.caption("💡 建议勾选以获得完整安全报告")
    
    # 操作按钮
    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        if st.button("📊 开始评估", type="primary", use_container_width=True, key="btn_eval"):
            if password:
                is_valid, error_msg = validate_password_input(password)
                if not is_valid:
                    st.error(f"❌ {error_msg}")
                else:
                    AppState.set('pending_action', "eval_password")
                    AppState.set('pending_password', password)
                    st.rerun()
            else:
                st.warning("请输入密码")
    
    with btn_col2:
        if st.button("🧹 清除结果", use_container_width=True, key="btn_clear"):
            AppState.set('pending_action', "clear_eval")
            st.rerun()
    
    # 显示评估结果
    if AppState.get('show_eval_result') and AppState.get('eval_result_cache'):
        result_data = AppState.get('eval_result_cache')
        eval_result = result_data['eval_result']
        is_pwned = result_data['is_pwned']
        pwned_count = result_data['pwned_count']
        leak_checked = result_data['leak_checked']
        evaluated_pwd = result_data.get('password', '')
        
        st.divider()
        
        # 显示当前评估的密码
        if evaluated_pwd:
            masked_pwd = evaluated_pwd[:2] + "*" * (len(evaluated_pwd) - 4) + evaluated_pwd[-2:] if len(evaluated_pwd) > 4 else "*" * len(evaluated_pwd)
            st.markdown(f"""
            <div class="evaluated-pwd">
                🔐 当前评估密码: <b>{masked_pwd}</b>（{len(evaluated_pwd)}位）
            </div>
            """, unsafe_allow_html=True)
        
        # 泄露状态
        if leak_checked:
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
        else:
            st.markdown("""
            <div class="leak-unchecked">
                <h4 style="color: #b45309; margin-top: 0;">⚠️ 未检测泄露</h4>
                <p style="margin-bottom: 0;">您未勾选泄露检测。建议勾选以获得完整安全报告。</p>
            </div>
            """, unsafe_allow_html=True)
        
        # 综合评分
        score_col, info_col = st.columns([1, 2])
        with score_col:
            score_color = eval_result['color']
            st.markdown(f"""
            <div style="text-align: center; padding: 1rem;">
                <div class="score-big" style="color: {score_color};">{eval_result['score']}</div>
                <div class="score-label" style="color: {score_color};">{safe_html(eval_result['level'])}</div>
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
        
        # 维度拆解
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
        
        if eval_result['patterns_found']:
            st.warning(f"⚠️ 检测到风险模式: {', '.join(eval_result['patterns_found'])}")
        
        # AI分析
        st.divider()
        st.subheader("🤖 AI风险深度解析")
        
        ai_cache_key = f"ai_{eval_result['score']}_{is_pwned}_{leak_checked}"
        if ai_cache_key not in st.session_state:
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
            st.session_state[ai_cache_key] = ai_result
        else:
            ai_result = st.session_state[ai_cache_key]
        
        st.markdown(f"""
        <div class="ai-card-risk">
            <h4 style="color: #475569; margin-top: 0;">🔍 风险解释</h4>
            <p style="color: #334155; line-height: 1.6;">{safe_html(ai_result['risk_explanation'])}</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="ai-card-advice">
            <h4 style="color: #166534; margin-top: 0;">💡 改进建议</h4>
            <p style="color: #14532d; line-height: 1.6;">{safe_html(ai_result['improvement_advice'])}</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="ai-card-tips">
            <h4 style="color: #1e40af; margin-top: 0;">📚 安全小贴士</h4>
            <p style="color: #1e3a8a; line-height: 1.6;">{safe_html(ai_result['security_tips'])}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # 改进清单
        st.divider()
        st.subheader("📋 快速改进清单")
        for i, suggestion in enumerate(eval_result['suggestions'], 1):
            st.write(f"{i}. {safe_html(suggestion)}")
        
        # ===== 修复：替代密码区域 =====
        st.divider()
        
        # 生成替代密码按钮
        if st.button("🔑 生成替代密码", type="secondary", key="btn_gen_alt"):
            # 使用Pending Action机制
            AppState.set('pending_alt_gen', True)
            AppState.set('pending_alt_length', eval_result['length'])
            st.rerun()  # 必须rerun，让顶部处理pending action
        
        # 显示替代密码（从session_state读取，确保一致性）
        alt_pwd = AppState.get('alt_password')
        alt_eval = AppState.get('alt_eval')
        alt_entropy = AppState.get('alt_entropy')
        
        if alt_pwd and alt_eval:
            st.markdown("""
            <div class="alt-password-section">
                <h3 style="margin-top: 0; color: #1e293b;">✨ 为您生成的替代密码</h3>
            """, unsafe_allow_html=True)
            
            # 只保留一个密码显示框（黑色主题）
            st.markdown(f'<div class="alt-password-code">{alt_pwd}</div>', unsafe_allow_html=True)
            
            # ===== 新增：可复制白色密码框 =====
            st.code(alt_pwd, language=None)
            st.caption("👆 悬停密码框点击右上角复制")

            # 操作按钮行
            col_a1, col_a2 = st.columns(2)
            
            with col_a1:
                # 重新生成按钮 - 使用Pending Action
                if st.button("🔄 重新生成", key="btn_regen_alt", use_container_width=True):
                    AppState.set('pending_alt_gen', True)
                    AppState.set('pending_alt_length', eval_result['length'])
                    st.rerun()
            
            with col_a2:
                # 评估此密码按钮
                if st.button("📊 评估此密码", key="btn_eval_alt", use_container_width=True):
                    AppState.clear_eval()
                    AppState.set('eval_input', alt_pwd)
                    AppState.set('pending_action', "eval_password")
                    AppState.set('pending_password', alt_pwd)
                    st.rerun()
            
            # 密码信息
            st.write(f"**评分**: {alt_eval.get('score', 'N/A')}/100 ({alt_eval.get('level', '未知')})")
            st.write(f"**熵值**: {alt_entropy:.1f} bits")
            
            st.markdown("</div>", unsafe_allow_html=True)
        
        st.caption("🔒 本次分析已完成，密码已从内存中清除")


# ============================================================
# 页面：生成密码
# ============================================================
elif AppState.get('current_page') == AppState.PAGE_GEN:
    st.header("🔑 智能密码生成器")
    
    # 自然语言输入
    st.subheader("💬 描述您的密码需求（可选）")
    user_desc = st.text_area(
        "用自然语言描述",
        value=AppState.get('user_desc'),
        placeholder="例如：16位工作邮箱密码，容易口述给同事...",
        help="AI将根据描述自动调整生成参数",
        key="user_desc_widget"
    )
    AppState.set('user_desc', user_desc)
    
    # 解析描述
    def parse_desc(desc):
        params = {'length': 16, 'mode': AppState.MODE_RANDOM, 'ambig': True}
        if not desc:
            return params
        import re
        m = re.search(r'(\d+)\s*位', desc)
        if m:
            params['length'] = min(32, max(8, int(m.group(1))))
        d = desc.lower()
        if any(w in d for w in ['口令', '单词', 'passphrase']):
            params['mode'] = AppState.MODE_PASSPHRASE
        elif any(w in d for w in ['易记', '记忆', 'memorable', '好记', '口述']):
            params['mode'] = AppState.MODE_MEMORABLE
        if any(w in d for w in ['口述', '口头', '告诉', '念']):
            params['ambig'] = True
        return params
    
    parsed = parse_desc(user_desc)
    
    if user_desc.strip():
        with st.expander("🤖 AI解析建议", expanded=True):
            modes = ["随机密码", "口令密码", "易记密码"]
            st.write(f"**建议长度**: {parsed['length']} 位")
            st.write(f"**建议模式**: {modes[parsed['mode']]}")
    
    # 模式选择
    mode_options = ["🎲 随机密码", "📝 口令密码", "💭 易记密码"]
    default_mode = parsed['mode'] if user_desc.strip() else AppState.get('gen_mode')
    
    gen_mode = st.radio(
        "选择生成模式",
        mode_options,
        horizontal=True,
        index=default_mode,
        key="gen_mode_widget"
    )
    selected_mode = mode_options.index(gen_mode)
    AppState.set('gen_mode', selected_mode)
    
    # ========== 随机密码模式 ==========
    if selected_mode == AppState.MODE_RANDOM:
        st.subheader("配置参数")
        
        default_len = parsed['length'] if user_desc.strip() else AppState.get('rand_length')
        
        col1, col2 = st.columns(2)
        with col1:
            length = st.slider("长度", 8, 32, default_len, key="rand_len_widget")
            AppState.set('rand_length', length)
        with col2:
            strength = st.selectbox("强度", ["强（推荐）", "极强"], key="rand_str_widget")
        
        st.write("**字符类型**:")
        c1, c2, c3, c4 = st.columns(4)
        with c1: 
            lower = st.checkbox("小写", AppState.get('rand_lower'), key="rand_l_widget")
            AppState.set('rand_lower', lower)
        with c2: 
            upper = st.checkbox("大写", AppState.get('rand_upper'), key="rand_u_widget")
            AppState.set('rand_upper', upper)
        with c3: 
            digit = st.checkbox("数字", AppState.get('rand_digit'), key="rand_d_widget")
            AppState.set('rand_digit', digit)
        with c4: 
            symbol = st.checkbox("符号", AppState.get('rand_symbol'), key="rand_s_widget")
            AppState.set('rand_symbol', symbol)
        
        ambig = st.checkbox("排除易混淆字符", AppState.get('rand_ambig'), key="rand_a_widget")
        AppState.set('rand_ambig', ambig)
        
        if st.button("✨ 生成随机密码", type="primary", key="btn_gen_rand"):
            if not any([lower, upper, digit, symbol]):
                st.error("请至少选择一种字符类型")
            else:
                AppState.set('pending_action', "gen_password")
                AppState.set('pending_gen_params', {
                    'mode': AppState.MODE_RANDOM,
                    'length': length if strength == "强（推荐）" else max(20, length),
                    'lower': lower, 'upper': upper, 'digit': digit, 'symbol': symbol,
                    'ambig': ambig
                })
                st.rerun()
    
    # ========== 口令密码模式 ==========
    elif selected_mode == AppState.MODE_PASSPHRASE:
        st.subheader("配置参数")
        
        default_w = parsed['length'] // 4 if user_desc.strip() else AppState.get('pp_words')
        
        col1, col2 = st.columns(2)
        with col1:
            words = st.slider("单词数", 3, 6, default_w, key="pp_w_widget")
            AppState.set('pp_words', words)
        with col2:
            sep = st.selectbox("分隔符", ["-", "_", ".", " "], 
                              index=["-", "_", ".", " "].index(AppState.get('pp_sep')),
                              key="pp_sep_widget")
            AppState.set('pp_sep', sep)
        
        num = st.checkbox("添加数字", AppState.get('pp_num'), key="pp_n_widget")
        AppState.set('pp_num', num)
        sym = st.checkbox("添加符号", AppState.get('pp_sym'), key="pp_s_widget")
        AppState.set('pp_sym', sym)
        
        if st.button("✨ 生成口令", type="primary", key="btn_gen_pp"):
            AppState.set('pending_action', "gen_password")
            AppState.set('pending_gen_params', {
                'mode': AppState.MODE_PASSPHRASE,
                'words': words, 'sep': sep, 'num': num, 'sym': sym
            })
            st.rerun()
    
    # ========== 易记密码模式 ==========
    else:
        st.subheader("配置参数")
        
        default_w = parsed['length'] // 5 if user_desc.strip() else AppState.get('mem_words')
        
        col1, col2 = st.columns(2)
        with col1:
            words = st.slider("单词数", 2, 4, default_w, key="mem_w_widget")
            AppState.set('mem_words', words)
        with col2:
            sep = st.selectbox("分隔符", ["-", "_", "."],
                              index=["-", "_", "."].index(AppState.get('mem_sep')),
                              key="mem_sep_widget")
            AppState.set('mem_sep', sep)
        
        cap = st.checkbox("随机大写", AppState.get('mem_cap'), key="mem_c_widget")
        AppState.set('mem_cap', cap)
        num = st.checkbox("添加数字", AppState.get('mem_num'), key="mem_n_widget")
        AppState.set('mem_num', num)
        
        if st.button("✨ 生成易记密码", type="primary", key="btn_gen_mem"):
            AppState.set('pending_action', "gen_password")
            AppState.set('pending_gen_params', {
                'mode': AppState.MODE_MEMORABLE,
                'words': words, 'sep': sep, 'cap': cap, 'num': num
            })
            st.rerun()
    
    # ========== 显示生成结果 ==========
    if AppState.get('show_gen_result') and AppState.get('gen_result_cache'):
        result = AppState.get('gen_result_cache')
        pwd = result['password']
        entropy = result['entropy']
        eval_res = result['eval']
        result_mode = result.get('mode', AppState.MODE_RANDOM)
        
        # 验证模式一致性
        if result_mode != selected_mode:
            st.warning("⚠️ 生成结果与当前模式不一致，请重新生成")
        
        st.divider()
        st.subheader("✨ 生成结果")
        
        st.markdown(f'<div class="pwd-box">{pwd}</div>', unsafe_allow_html=True)
        st.code(pwd, language=None)
        
        col_g1, col_g2, col_g3 = st.columns(3)
        
        with col_g1:
            st.caption("👆 悬停密码框点击右上角复制")
        
        with col_g2:
            # ===== 修复：重新生成使用Pending Action =====
            if st.button("🔄 重新生成", key="btn_regen"):
                AppState.set('pending_regen', True)
                st.rerun()
        
        with col_g3:
            if st.button("📊 去评估此密码", key="btn_goto_eval"):
                AppState.clear_eval()
                AppState.set('eval_input', pwd)
                AppState.set('pending_action', "eval_password")
                AppState.set('pending_password', pwd)
                AppState.set('current_page', AppState.PAGE_EVAL)
                st.rerun()
        
        # 显示信息
        st.write(f"**评分**: {eval_res.get('score', 'N/A')}/100 ({eval_res.get('level', '未知')})")
        st.write(f"**熵值**: {entropy:.1f} bits")
        
        parts = []
        if eval_res.get('has_lower'): parts.append("小写字母")
        if eval_res.get('has_upper'): parts.append("大写字母")
        if eval_res.get('has_digit'): parts.append("数字")
        if eval_res.get('has_symbol'): parts.append("符号")
        if parts:
            st.write(f"**包含**: {', '.join(parts)}")


# ============================================================
# 页面：安全指南
# ============================================================
else:
    st.header("📖 密码安全最佳实践")
    
    with st.expander("🔐 核心原则", expanded=True):
        st.markdown("""
        ### 1. 长度胜过复杂度
        **16位以上的随机密码**比8位复杂密码更安全。
        
        ### 2. 每个账户唯一
        绝不重复使用密码。使用密码管理器（Bitwarden、1Password）。
        
        ### 3. 启用双因素认证 (2FA)
        硬件密钥 (YubiKey) > 认证器App > 短信验证码
        
        ### 4. 定期检查泄露
        使用 [Have I Been Pwned](https://haveibeenpwned.com) 检查。
        """)
    
    with st.expander("🛡️ 推荐工具"):
        st.markdown("""
        | 工具 | 类型 | 特点 |
        |-----|------|------|
        | Bitwarden | 密码管理器 | 开源免费，跨平台 |
        | 1Password | 密码管理器 | 商业软件，体验优秀 |
        | KeePassXC | 密码管理器 | 完全离线 |
        | YubiKey | 硬件密钥 | 最高安全性 |
        """)
    
    with st.expander("❓ 常见问题"):
        st.markdown("""
        **Q: 本工具会保存我的密码吗？**  
        A: **不会。** 密码仅在处理请求时短暂存在于服务端内存中，响应后立即释放。
        
        **Q: 为什么需要输入真实密码？**  
        A: 只有真实密码才能准确评估强度和检测泄露。建议在私密网络环境下使用。
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
</div>
""", unsafe_allow_html=True)