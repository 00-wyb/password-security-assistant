"""
智能密码安全助手 - 增强版
新增功能：
1. 批量密码评估
2. 场景标签
3. 密码对比分析
4. 密码管理器向导
5. 实时输入提示
"""

import streamlit as st
from datetime import datetime
from hibp_client import check_pwned
from password_evaluator import evaluate_password
from ai_client import AIClient
from password_generator import (
    generate_random_password, 
    generate_passphrase, 
    generate_memorable_password
)
from security_utils import safe_html, sanitize_input, validate_password_input
from batch_evaluator import batch_evaluate, batch_summary, export_batch_csv
from scenario_config import (
    SCENARIOS, get_scenario_config, 
    get_scenario_adjusted_score, get_scenario_status
)
from password_manager_guide import (
    get_manager_guide, get_all_managers, generate_save_guide
)


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
    PAGE_BATCH = "batch"  # 新增：批量评估页
    PAGE_COMPARE = "compare"  # 新增：密码对比页
    PAGE_MANAGER = "manager"  # 新增：管理器向导页

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
            'eval_scenario': "general",  # 新增：场景标签

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

            # 替代密码
            'alt_password': "",
            'alt_eval': None,
            'alt_entropy': 0,
            'pending_alt_gen': False,
            'pending_alt_length': 16,

            # 待处理操作
            'pending_action': None,
            'pending_password': "",
            'pending_gen_params': None,
            'pending_regen': False,

            # 批量评估状态
            'batch_input': "",  # 新增
            'batch_results': None,  # 新增
            'batch_check_leak': True,  # 新增

            # 密码对比状态
            'compare_old_pwd': "",  # 新增
            'compare_new_pwd': "",  # 新增
            'compare_result': None,  # 新增

            # 管理器向导状态
            'selected_manager': "bitwarden",  # 新增
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

    @staticmethod
    def clear_batch():
        """清除批量评估状态"""
        st.session_state['batch_input'] = ""
        st.session_state['batch_results'] = None


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


# 处理替代密码的Pending Action
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


# 处理生成器重新生成的Pending Action
if AppState.get('pending_regen'):
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


# ========== CSS样式（增强版）==========
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
    /* 新增：场景标签样式 */
    .scenario-tag {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 500;
        margin: 0.25rem;
    }
    .scenario-general { background-color: #e0e7ff; color: #3730a3; }
    .scenario-email { background-color: #fce7f3; color: #be185d; }
    .scenario-banking { background-color: #fee2e2; color: #991b1b; }
    .scenario-work { background-color: #dbeafe; color: #1e40af; }
    .scenario-other { background-color: #f3f4f6; color: #4b5563; }
    /* 新增：实时提示样式 */
    .realtime-tip {
        padding: 0.5rem 1rem;
        border-radius: 6px;
        font-size: 0.9rem;
        margin: 0.25rem 0;
        animation: fadeIn 0.3s ease-in;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-5px); }
        to { opacity: 1; transform: translateY(0); }
    }
    /* 新增：对比样式 */
    .compare-card {
        background-color: #f8fafc;
        border: 2px solid #e2e8f0;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 0.5rem;
    }
    .compare-better { border-color: #10b981; background-color: #ecfdf5; }
    .compare-worse { border-color: #ef4444; background-color: #fef2f2; }
    /* 新增：批量评估样式 */
    .batch-summary {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
    }
    @media (max-width: 768px) {
        .score-big { font-size: 2rem; }
        .score-label { font-size: 1rem; }
    }
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
            "基于AI增强的密码安全检测工具 · 增强版</p>", 
            unsafe_allow_html=True)


# ========== 页面切换按钮（6个页面）==========
col_nav1, col_nav2, col_nav3, col_nav4, col_nav5, col_nav6 = st.columns(6)

with col_nav1:
    eval_active = AppState.get('current_page') == AppState.PAGE_EVAL
    if st.button("🔍 评估", type="primary" if eval_active else "secondary", 
                 use_container_width=True, key="nav_eval"):
        AppState.set('current_page', AppState.PAGE_EVAL)
        st.rerun()

with col_nav2:
    gen_active = AppState.get('current_page') == AppState.PAGE_GEN
    if st.button("🔑 生成", type="primary" if gen_active else "secondary",
                 use_container_width=True, key="nav_gen"):
        AppState.set('current_page', AppState.PAGE_GEN)
        st.rerun()

with col_nav3:
    batch_active = AppState.get('current_page') == AppState.PAGE_BATCH
    if st.button("📋 批量", type="primary" if batch_active else "secondary",
                 use_container_width=True, key="nav_batch"):
        AppState.set('current_page', AppState.PAGE_BATCH)
        st.rerun()

with col_nav4:
    compare_active = AppState.get('current_page') == AppState.PAGE_COMPARE
    if st.button("⚖️ 对比", type="primary" if compare_active else "secondary",
                 use_container_width=True, key="nav_compare"):
        AppState.set('current_page', AppState.PAGE_COMPARE)
        st.rerun()

with col_nav5:
    manager_active = AppState.get('current_page') == AppState.PAGE_MANAGER
    if st.button("💾 保存", type="primary" if manager_active else "secondary",
                 use_container_width=True, key="nav_manager"):
        AppState.set('current_page', AppState.PAGE_MANAGER)
        st.rerun()

with col_nav6:
    guide_active = AppState.get('current_page') == AppState.PAGE_GUIDE
    if st.button("📖 指南", type="primary" if guide_active else "secondary",
                 use_container_width=True, key="nav_guide"):
        AppState.set('current_page', AppState.PAGE_GUIDE)
        st.rerun()

st.divider()


# ============================================================
# 页面：评估密码（增强版：实时提示 + 场景标签）
# ============================================================
if AppState.get('current_page') == AppState.PAGE_EVAL:
    st.header("🔍 密码强度评估")

    # ===== 场景标签选择 =====
    st.subheader("🏷️ 使用场景")
    scenario_cols = st.columns(len(SCENARIOS))

    for i, (key, config) in enumerate(SCENARIOS.items()):
        with scenario_cols[i]:
            is_selected = AppState.get('eval_scenario') == key
            btn_type = "primary" if is_selected else "secondary"
            if st.button(
                f"{config['icon']} {config['name']}",
                type=btn_type,
                use_container_width=True,
                key=f"scenario_{key}"
            ):
                AppState.set('eval_scenario', key)
                st.rerun()

    # 显示当前场景说明
    current_scenario = get_scenario_config(AppState.get('eval_scenario'))
    st.caption(f"📌 {current_scenario['description']} | 最低要求: {current_scenario['min_score']}分 | 推荐: {current_scenario['recommended_score']}分")

    if current_scenario.get('warning'):
        st.info(f"💡 {current_scenario['warning']}")

    st.divider()

    # ===== 密码输入（带实时提示）=====
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

    # ===== 实时输入提示（核心新增功能）=====
    if password:
        realtime_eval = evaluate_password(password)

        # 实时进度条
        st.progress(realtime_eval['score'] / 100)

        # 动态提示区域
        tip_container = st.container()

        with tip_container:
            tips = []

            # 长度提示
            if len(password) < 8:
                tips.append(("🔴", "长度不足8位，极易被暴力破解", "#fee2e2"))
            elif len(password) < 12:
                tips.append(("🟡", f"当前{len(password)}位，建议增至12位以上", "#fef3c7"))
            elif len(password) >= 16:
                tips.append(("🟢", f"✓ 长度优秀（{len(password)}位）", "#d1fae5"))

            # 字符种类提示
            missing_types = []
            if not realtime_eval['has_lower']: missing_types.append("小写字母")
            if not realtime_eval['has_upper']: missing_types.append("大写字母")
            if not realtime_eval['has_digit']: missing_types.append("数字")
            if not realtime_eval['has_symbol']: missing_types.append("符号")

            if missing_types:
                tips.append(("🟡", f"建议添加: {', '.join(missing_types)}", "#fef3c7"))
            else:
                tips.append(("🟢", "✓ 字符种类完整（4/4）", "#d1fae5"))

            # 模式检测提示
            if realtime_eval['patterns_found']:
                tips.append(("🔴", f"⚠️ 检测到风险: {realtime_eval['patterns_found'][0]}", "#fee2e2"))

            # 场景化提示
            scenario_status = get_scenario_status(realtime_eval['score'], AppState.get('eval_scenario'))
            if scenario_status['status'] == 'danger':
                tips.append(("🔴", scenario_status['message'], "#fee2e2"))
            elif scenario_status['status'] == 'acceptable':
                tips.append(("🟡", scenario_status['message'], "#fef3c7"))

            # 显示提示
            for icon, text, bg_color in tips:
                st.markdown(f"""
                <div class="realtime-tip" style="background-color: {bg_color};">
                    {icon} {text}
                </div>
                """, unsafe_allow_html=True)

        # 实时强度徽章
        badge_color = "#ef4444" if realtime_eval['score'] < 40 else "#f59e0b" if realtime_eval['score'] < 70 else "#10b981"
        st.markdown(f"""
        <div style="text-align: center; margin: 0.5rem 0;">
            <span style="font-size: 1.5rem; font-weight: bold; color: {badge_color};">
                {'🔴' if realtime_eval['score'] < 40 else '🟡' if realtime_eval['score'] < 70 else '🟢'} 
                实时强度: {realtime_eval['level']} ({realtime_eval['score']}/100)
            </span>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # ===== 泄露检测选项 =====
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

    # ===== 操作按钮 =====
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


    # ===== 显示评估结果 =====
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
            masked_pwd = evaluated_pwd[:2] + "***" + evaluated_pwd[-2:] if len(evaluated_pwd) > 4 else "****"
            st.markdown(f"""
            <div class="evaluated-pwd">
                🔐 当前评估密码: <b>{masked_pwd}</b>（{len(evaluated_pwd)}位）
            </div>
            """, unsafe_allow_html=True)

        # ===== 场景化评分展示 =====
        scenario_key = AppState.get('eval_scenario')
        scenario_config = get_scenario_config(scenario_key)
        scenario_status = get_scenario_status(eval_result['score'], scenario_key)

        st.markdown(f"""
        <div style="margin: 1rem 0; padding: 0.75rem; background-color: {scenario_status['color']}15; 
                    border-left: 4px solid {scenario_status['color']}; border-radius: 4px;">
            <span class="scenario-tag scenario-{scenario_key.replace('_', '-')}">
                {scenario_config['icon']} {scenario_config['name']}
            </span>
            <span style="color: {scenario_status['color']}; font-weight: 600;">
                {scenario_status['message']}
            </span>
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

        ai_cache_key = f"ai_{eval_result['score']}_{is_pwned}_{leak_checked}_{scenario_key}"
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

        # ===== 下载评估报告 ===== 【新增】
        st.divider()
        st.subheader("📥 评估报告导出")

        # 构建报告内容
        report_lines = [
            "=" * 60,
            "🔐 智能密码安全助手 - 密码评估报告",
            "=" * 60,
            "",
            f"评估时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"使用场景: {scenario_config['icon']} {scenario_config['name']}",
            "",
            "-" * 60,
            "【密码信息】",
            "-" * 60,
            f"密码长度: {eval_result['length']} 位",
            f"密码脱敏: {evaluated_pwd[:2] + '*' * (len(evaluated_pwd) - 4) + evaluated_pwd[-2:] if len(evaluated_pwd) > 4 else '****'}",
            "",
            "-" * 60,
            "【综合评分】",
            "-" * 60,
            f"综合评分: {eval_result['score']}/100",
            f"安全等级: {eval_result['level']}",
            f"熵值估计: {eval_result['entropy']} bits",
            "",
            "-" * 60,
            "【维度拆解】",
            "-" * 60,
            f"长度评分: {eval_result['length_score']}/40",
            f"复杂度评分: {eval_result['complexity_score']}/30",
            f"模式安全: {eval_result['pattern_score']}/30",
            f"熵值评分: {eval_result['entropy_score']}/25",
            "",
            "-" * 60,
            "【字符组成】",
            "-" * 60,
            f"小写字母: {'✓ 有' if eval_result['has_lower'] else '✗ 无'}",
            f"大写字母: {'✓ 有' if eval_result['has_upper'] else '✗ 无'}",
            f"数字: {'✓ 有' if eval_result['has_digit'] else '✗ 无'}",
            f"特殊符号: {'✓ 有' if eval_result['has_symbol'] else '✗ 无'}",
            f"字符种类: {eval_result['char_types']}/4",
            "",
            "-" * 60,
            "【泄露检测】",
            "-" * 60,
        ]

        if leak_checked:
            if pwned_count == -1:
                report_lines.append("泄露状态: ⚠️ 查询失败（HIBP服务暂时不可用）")
            elif is_pwned:
                report_lines.append(f"泄露状态: 🔴 已泄露 {pwned_count:,} 次")
                report_lines.append("紧急建议: 请立即在所有使用该密码的网站上更换密码")
            else:
                report_lines.append("泄露状态: ✅ 未泄露")
                report_lines.append("该密码未在已知泄露数据库中发现")
        else:
            report_lines.append("泄露状态: ⚠️ 未检测（用户未勾选泄露检测）")
            report_lines.append("建议: 勾选泄露检测以获得完整安全报告")

        report_lines.extend([
            "",
            "-" * 60,
            "【AI风险解析】",
            "-" * 60,
            f"风险解释: {ai_result['risk_explanation']}",
            "",
            f"改进建议: {ai_result['improvement_advice']}",
            "",
            f"安全贴士: {ai_result['security_tips']}",
            "",
            "-" * 60,
            "【改进清单】",
            "-" * 60,
        ])

        for i, suggestion in enumerate(eval_result['suggestions'], 1):
            report_lines.append(f"{i}. {suggestion}")

        report_lines.extend([
            "",
            "-" * 60,
            "【场景评估】",
            "-" * 60,
            f"场景: {scenario_config['name']}",
            f"场景要求: 最低 {scenario_config['min_score']} 分 / 推荐 {scenario_config['recommended_score']} 分",
            f"评估结果: {scenario_status['message']}",
            "",
            "=" * 60,
            "⚠️ 安全声明",
            "=" * 60,
            "1. 本报告由智能密码安全助手自动生成",
            "2. 密码仅在评估时短暂存在于服务端内存中，响应后立即销毁",
            "3. 本工具不保存、不记录、不持久化任何密码数据",
            "4. 建议在私密网络环境下使用本工具",
            "5. 如密码已泄露，请立即在所有相关网站更换",
            "",
            "=" * 60,
        ])

        report_content = "\n".join(report_lines)

        # 下载按钮
        col_download1, col_download2 = st.columns([1, 2])
        with col_download1:
            st.download_button(
                label="📥 下载评估报告",
                data=report_content,
                file_name=f"密码评估报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True,
                key="btn_download_eval_report"
            )
        with col_download2:
            st.caption("报告包含脱敏后的评估结果，不含密码明文")

        # 替代密码区域
        st.divider()

        if st.button("🔑 生成替代密码", type="secondary", key="btn_gen_alt"):
            AppState.set('pending_alt_gen', True)
            AppState.set('pending_alt_length', eval_result['length'])
            st.rerun()

        alt_pwd = AppState.get('alt_password')
        alt_eval = AppState.get('alt_eval')
        alt_entropy = AppState.get('alt_entropy')

        if alt_pwd and alt_eval:
            st.markdown("""
            <div class="alt-password-section">
                <h3 style="margin-top: 0; color: #1e293b;">✨ 为您生成的替代密码</h3>
            """, unsafe_allow_html=True)

            st.markdown(f'<div class="alt-password-code">{alt_pwd}</div>', unsafe_allow_html=True)
            st.code(alt_pwd, language=None)
            st.caption("👆 悬停密码框点击右上角复制")

            col_a1, col_a2, col_a3 = st.columns(3)

            with col_a1:
                if st.button("🔄 重新生成", key="btn_regen_alt", use_container_width=True):
                    AppState.set('pending_alt_gen', True)
                    AppState.set('pending_alt_length', eval_result['length'])
                    st.rerun()

            with col_a2:
                if st.button("📊 评估此密码", key="btn_eval_alt", use_container_width=True):
                    AppState.clear_eval()
                    AppState.set('eval_input', alt_pwd)
                    AppState.set('pending_action', "eval_password")
                    AppState.set('pending_password', alt_pwd)
                    st.rerun()

            with col_a3:
                download_content = f"""智能密码安全助手 - 替代密码导出

生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
密码类型: 替代密码（随机生成）
密码长度: {len(alt_pwd)} 位
强度评分: {alt_eval.get('score', 'N/A')}/100 ({alt_eval.get('level', '未知')})
熵值: {alt_entropy:.1f} bits

⚠️ 安全提醒: 请妥善保管此密码，不要在不安全的环境中存储或传输。

密码内容:
{alt_pwd}
"""
                st.download_button(
                    label="📥 下载密码",
                    data=download_content,
                    file_name=f"替代密码_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True,
                    key="btn_download_alt"
                )

            st.write(f"**评分**: {alt_eval.get('score', 'N/A')}/100 ({alt_eval.get('level', '未知')})")
            st.write(f"**熵值**: {alt_entropy:.1f} bits")

            st.markdown("</div>", unsafe_allow_html=True)

        st.caption("🔒 本次分析已完成，密码已从内存中清除")

# ============================================================
# 页面：批量评估（新增）
# ============================================================
elif AppState.get('current_page') == AppState.PAGE_BATCH:
    st.header("📋 批量密码评估")
    st.markdown("一次性评估多个密码，生成安全汇总报告")

    # 输入区域
    st.subheader("📝 输入密码列表")
    st.caption("每行输入一个密码，最多50个，空行将被忽略")

    batch_input = st.text_area(
        "密码列表",
        value=AppState.get('batch_input'),
        placeholder="password1\n123456\nMyP@ssw0rd2024!\n...",
        height=200,
        key="batch_input_widget",
        help="每行一个密码，支持最多50个密码"
    )
    AppState.set('batch_input', batch_input)

    # 选项
    col_b1, col_b2 = st.columns([1, 3])
    with col_b1:
        batch_leak = st.checkbox(
            "检查泄露（较慢，每个密码需1-2秒）",
            value=AppState.get('batch_check_leak', True),
            key="batch_leak_check"
        )
        AppState.set('batch_check_leak', batch_leak)
    with col_b2:
        st.caption("💡 建议先不勾选泄露检查快速评估，再对高风险密码单独检查")

    # 操作按钮
    btn_col1, btn_col2, btn_col3 = st.columns(3)

    with btn_col1:
        if st.button("📊 开始批量评估", type="primary", use_container_width=True, key="btn_batch_eval"):
            passwords = [p.strip() for p in batch_input.split("\n") if p.strip()]

            if not passwords:
                st.warning("请输入至少一个密码")
            elif len(passwords) > 50:
                st.error("密码数量超过50个限制，请减少后重试")
            else:
                with st.spinner(f"正在评估 {len(passwords)} 个密码..."):
                    results = batch_evaluate(passwords, check_leak=batch_leak)
                    AppState.set('batch_results', results)
                st.success(f"✅ 评估完成！共 {len(results)} 个密码")

    with btn_col2:
        if st.button("🧹 清空评估结果", use_container_width=True, key="btn_batch_clear"):
            AppState.clear_batch()
            st.rerun()

    with btn_col3:
        batch_results = AppState.get('batch_results')
        if batch_results:
            csv_content = export_batch_csv(batch_results)
            st.download_button(
                label="📥 导出CSV",
                data=csv_content,
                file_name=f"批量评估报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
                key="btn_batch_export"
            )

    # 显示结果
    batch_results = AppState.get('batch_results')
    if batch_results:
        st.divider()

        # 汇总统计
        summary = batch_summary(batch_results)

        st.subheader("📊 汇总统计")

        # 汇总卡片
        st.markdown(f"""
        <div class="batch-summary">
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; text-align: center;">
                <div>
                    <div style="font-size: 2rem; font-weight: bold;">{summary['total']}</div>
                    <div style="font-size: 0.9rem; opacity: 0.9;">总数量</div>
                </div>
                <div>
                    <div style="font-size: 2rem; font-weight: bold;">{summary['average_score']}</div>
                    <div style="font-size: 0.9rem; opacity: 0.9;">平均评分</div>
                </div>
                <div>
                    <div style="font-size: 2rem; font-weight: bold; color: {'#fecaca' if summary['risky_count'] > 0 else '#bbf7d0'};">
                        {summary['risky_count']}
                    </div>
                    <div style="font-size: 0.9rem; opacity: 0.9;">风险密码</div>
                </div>
                <div>
                    <div style="font-size: 2rem; font-weight: bold; color: {'#fecaca' if summary['pwned_count'] > 0 else '#bbf7d0'};">
                        {summary['pwned_count']}
                    </div>
                    <div style="font-size: 0.9rem; opacity: 0.9;">已泄露</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 等级分布
        col_dist1, col_dist2 = st.columns(2)

        with col_dist1:
            st.write("**等级分布**")
            for level, count in summary['level_distribution'].items():
                color = {"极强": "🟢", "强": "🟢", "中等": "🟡", "弱": "🔴", "极弱": "🔴"}.get(level, "⚪")
                st.write(f"{color} {level}: {count} 个")

        with col_dist2:
            st.write("**安全统计**")
            st.write(f"🟢 强密码: {summary['strong_count']} 个")
            st.write(f"🟡 中等: {summary['medium_count']} 个")
            st.write(f"🔴 弱密码: {summary['weak_count']} 个")
            if summary['failed_checks'] > 0:
                st.write(f"⚠️ 泄露查询失败: {summary['failed_checks']} 个")

        # 风险警告
        if summary['overall_risk'] == "高":
            st.error("🚨 检测到高风险！存在已泄露或极弱密码，请立即处理")
        elif summary['overall_risk'] == "中":
            st.warning("⚠️ 存在中等风险密码，建议优化")
        else:
            st.success("✅ 整体安全状况良好")

        # 详细结果表格
        st.divider()
        st.subheader("📋 详细结果")

        # 排序选项
        sort_col1, sort_col2 = st.columns(2)
        with sort_col1:
            sort_by = st.selectbox(
                "排序方式",
                ["评分(低→高)", "评分(高→低)", "泄露次数", "长度"],
                key="batch_sort"
            )
        with sort_col2:
            filter_level = st.multiselect(
                "筛选等级",
                ["极强", "强", "中等", "弱", "极弱"],
                default=["极强", "强", "中等", "弱", "极弱"],
                key="batch_filter"
            )

        # 排序和筛选
        display_results = batch_results.copy()

        if sort_by == "评分(低→高)":
            display_results.sort(key=lambda x: x['score'])
        elif sort_by == "评分(高→低)":
            display_results.sort(key=lambda x: x['score'], reverse=True)
        elif sort_by == "泄露次数":
            display_results.sort(key=lambda x: x['pwned_count'] if x['pwned_count'] >= 0 else 0, reverse=True)
        elif sort_by == "长度":
            display_results.sort(key=lambda x: x['length'])

        display_results = [r for r in display_results if r['level'] in filter_level]

        # 显示表格
        for r in display_results:
            leak_badge = ""
            if r['is_pwned']:
                leak_badge = f"<span style='color: #dc2626; font-weight: bold;'>🔴 已泄露 {r['pwned_count']:,} 次</span>"
            elif r['pwned_count'] == -1:
                leak_badge = "<span style='color: #f59e0b;'>⚠️ 查询失败</span>"
            else:
                leak_badge = "<span style='color: #059669;'>✅ 未泄露</span>"

            risk_patterns = ", ".join(r['patterns_found']) if r['patterns_found'] else "无"

            with st.expander(f"#{r['index']} {r['masked']} | 评分: {r['score']} ({r['level']}) | {leak_badge}", 
                            expanded=r['score'] < 40 or r['is_pwned']):

                col1, col2 = st.columns([1, 2])

                with col1:
                    st.write(f"**长度**: {r['length']} 位")
                    st.write(f"**熵值**: {r['entropy']} bits")
                    st.write(f"**字符种类**: {r['char_types']}/4")

                with col2:
                    st.write(f"**风险模式**: {risk_patterns}")
                    if r['suggestions']:
                        st.write("**建议**:")
                        for s in r['suggestions'][:2]:
                            st.write(f"• {s}")



# ============================================================
# 页面：密码对比（新增）
# ============================================================
elif AppState.get('current_page') == AppState.PAGE_COMPARE:
    st.header("⚖️ 密码对比分析")
    st.markdown("对比新旧密码，直观展示安全提升")

    # 输入区域
    col_old, col_new = st.columns(2)

    with col_old:
        st.subheader("🔴 旧密码")
        old_pwd = st.text_input(
            "输入旧密码",
            type="password",
            value=AppState.get('compare_old_pwd'),
            key="compare_old_widget",
            placeholder="输入当前使用的密码..."
        )
        AppState.set('compare_old_pwd', old_pwd)

    with col_new:
        st.subheader("🟢 新密码")
        new_pwd = st.text_input(
            "输入新密码",
            type="password",
            value=AppState.get('compare_new_pwd'),
            key="compare_new_widget",
            placeholder="输入新密码..."
        )
        AppState.set('compare_new_pwd', new_pwd)

    # 对比按钮
    if st.button("📊 开始对比", type="primary", use_container_width=True, key="btn_compare"):
        if not old_pwd or not new_pwd:
            st.warning("请输入旧密码和新密码")
        else:
            old_eval = evaluate_password(old_pwd)
            new_eval = evaluate_password(new_pwd)

            old_pwned, old_count = check_pwned(old_pwd)
            new_pwned, new_count = check_pwned(new_pwd)

            compare_data = {
                'old': {
                    'eval': old_eval,
                    'is_pwned': old_pwned,
                    'pwned_count': old_count,
                    'masked': old_pwd[:2] + "***" + old_pwd[-2:] if len(old_pwd) > 4 else "****"
                },
                'new': {
                    'eval': new_eval,
                    'is_pwned': new_pwned,
                    'pwned_count': new_count,
                    'masked': new_pwd[:2] + "***" + new_pwd[-2:] if len(new_pwd) > 4 else "****"
                }
            }
            AppState.set('compare_result', compare_data)

    # 显示对比结果
    compare_result = AppState.get('compare_result')
    if compare_result:
        st.divider()

        old_data = compare_result['old']
        new_data = compare_result['new']
        old_eval = old_data['eval']
        new_eval = new_data['eval']

        # 评分变化
        score_diff = new_eval['score'] - old_eval['score']

        st.subheader("📊 对比结果")

        # 总体评价
        if score_diff > 0 and not new_data['is_pwned']:
            st.success(f"✅ 安全提升！新密码评分提高了 {score_diff} 分")
        elif score_diff > 0 and new_data['is_pwned']:
            st.warning(f"⚠️ 评分提高 {score_diff} 分，但新密码已泄露！")
        elif score_diff < 0:
            st.error(f"🚨 安全下降！新密码评分降低了 {abs(score_diff)} 分")
        else:
            st.info("💡 评分相同，请检查其他维度差异")

        # 评分对比卡片
        col_card1, col_card2 = st.columns(2)

        with col_card1:
            old_color = old_eval['color']
            st.markdown(f"""
            <div class="compare-card {'compare-worse' if old_eval['score'] < new_eval['score'] else 'compare-better' if old_eval['score'] > new_eval['score'] else ''}">
                <h3 style="margin-top: 0; color: {old_color};">🔴 旧密码</h3>
                <div style="font-size: 2.5rem; font-weight: bold; color: {old_color}; text-align: center;">
                    {old_eval['score']}
                </div>
                <div style="text-align: center; color: {old_color}; font-weight: 600;">{old_eval['level']}</div>
                <hr>
                <p><b>长度</b>: {old_eval['length']} 位</p>
                <p><b>熵值</b>: {old_eval['entropy']} bits</p>
                <p><b>字符种类</b>: {old_eval['char_types']}/4</p>
                <p><b>泄露状态</b>: {'🔴 已泄露' if old_data['is_pwned'] else '✅ 未泄露'}</p>
            </div>
            """, unsafe_allow_html=True)

        with col_card2:
            new_color = new_eval['color']
            st.markdown(f"""
            <div class="compare-card {'compare-better' if new_eval['score'] > old_eval['score'] else 'compare-worse' if new_eval['score'] < old_eval['score'] else ''}">
                <h3 style="margin-top: 0; color: {new_color};">🟢 新密码</h3>
                <div style="font-size: 2.5rem; font-weight: bold; color: {new_color}; text-align: center;">
                    {new_eval['score']}
                </div>
                <div style="text-align: center; color: {new_color}; font-weight: 600;">{new_eval['level']}</div>
                <hr>
                <p><b>长度</b>: {new_eval['length']} 位</p>
                <p><b>熵值</b>: {new_eval['entropy']} bits</p>
                <p><b>字符种类</b>: {new_eval['char_types']}/4</p>
                <p><b>泄露状态</b>: {'🔴 已泄露' if new_data['is_pwned'] else '✅ 未泄露'}</p>
            </div>
            """, unsafe_allow_html=True)

        # 维度对比雷达图（简化版表格）
        st.subheader("📈 维度对比")

        compare_dims = {
            '长度评分': (old_eval['length_score'], new_eval['length_score'], 40),
            '复杂度评分': (old_eval['complexity_score'], new_eval['complexity_score'], 30),
            '模式安全': (old_eval['pattern_score'], new_eval['pattern_score'], 30),
            '熵值评分': (old_eval['entropy_score'], new_eval['entropy_score'], 25),
        }

        for dim_name, (old_val, new_val, max_val) in compare_dims.items():
            diff = new_val - old_val
            diff_icon = "🟢↑" if diff > 0 else "🔴↓" if diff < 0 else "⚪→"
            diff_color = "#10b981" if diff > 0 else "#ef4444" if diff < 0 else "#6b7280"

            col_d1, col_d2, col_d3 = st.columns([2, 2, 1])
            with col_d1:
                st.write(f"**{dim_name}**")
            with col_d2:
                st.write(f"旧: {old_val}/{max_val} → 新: {new_val}/{max_val}")
            with col_d3:
                st.markdown(f"<span style='color: {diff_color}; font-weight: bold;'>{diff_icon} {diff:+d}</span>", 
                           unsafe_allow_html=True)

        # 风险模式对比
        st.subheader("⚠️ 风险模式对比")
        old_patterns = set(old_eval['patterns_found'])
        new_patterns = set(new_eval['patterns_found'])

        fixed_patterns = old_patterns - new_patterns
        new_risks = new_patterns - old_patterns

        if fixed_patterns:
            st.success(f"✅ 已修复: {', '.join(fixed_patterns)}")
        if new_risks:
            st.error(f"🚨 新增风险: {', '.join(new_risks)}")
        if not fixed_patterns and not new_risks:
            st.info("💡 风险模式无变化")

        # 建议
        st.subheader("💡 对比建议")
        if new_eval['score'] < 70:
            st.warning("新密码仍不够强，建议使用密码生成器创建更强的密码")
        elif new_data['is_pwned']:
            st.error("新密码已泄露！必须完全更换，不要仅修改部分字符")
        elif score_diff > 20:
            st.success("安全提升显著！建议立即在所有网站更换为新密码")
        else:
            st.info("安全状况改善，建议逐步更换旧密码")


# ============================================================
# 页面：密码管理器向导（新增）
# ============================================================
elif AppState.get('current_page') == AppState.PAGE_MANAGER:
    st.header("💾 密码安全保存指南")
    st.markdown("选择适合您的密码管理器，安全保存生成的强密码")

    # 管理器选择
    managers = get_all_managers()

    st.subheader("🔧 选择密码管理器")

    manager_cols = st.columns(len(managers))
    for i, mgr in enumerate(managers):
        with manager_cols[i]:
            is_selected = AppState.get('selected_manager') == mgr['key']
            btn_type = "primary" if is_selected else "secondary"
            if st.button(
                f"{mgr['icon']} {mgr['name']}",
                type=btn_type,
                use_container_width=True,
                key=f"mgr_{mgr['key']}"
            ):
                AppState.set('selected_manager', mgr['key'])
                st.rerun()

    # 显示选中管理器的详细信息
    selected_key = AppState.get('selected_manager')
    guide = get_manager_guide(selected_key)

    st.divider()

    col_info, col_steps = st.columns([1, 2])

    with col_info:
        st.subheader(f"{guide['icon']} {guide['name']}")
        st.write(f"**类型**: {guide['type']}")
        st.write(f"**官网**: [{guide['url']}]({guide['url']})")

        st.write("**支持平台**:")
        for platform in guide['platforms']:
            st.write(f"• {platform}")

        st.write("**核心功能**:")
        for feature in guide['features']:
            st.write(f"• {feature}")

        st.write("**优势**:")
        for pro in guide['pros']:
            st.write(f"✅ {pro}")

        if guide.get('cons'):
            st.write("**不足**:")
            for con in guide['cons']:
                st.write(f"⚠️ {con}")

    with col_steps:
        st.subheader("📋 使用步骤")
        for i, step in enumerate(guide['steps'], 1):
            st.markdown(f"""
            <div style="padding: 0.75rem; margin: 0.5rem 0; background-color: #f8fafc; 
                        border-left: 4px solid #667eea; border-radius: 4px;">
                <b>步骤 {i}</b>: {step}
            </div>
            """, unsafe_allow_html=True)

        # 生成保存指南文本
        st.divider()

        if st.button("📄 生成保存指南文本", type="primary", key="btn_save_guide"):
            guide_text = generate_save_guide("", selected_key)
            st.text_area("保存指南", guide_text, height=300)

            st.download_button(
                label="📥 下载指南",
                data=guide_text,
                file_name=f"密码保存指南_{guide['name']}.txt",
                mime="text/plain",
                key="btn_download_guide"
            )

    # 通用安全提醒
    st.divider()
    st.subheader("⚠️ 通用安全提醒")

    reminders = [
        "**主密码是唯一需要记住的密码**，务必安全保管，建议使用纸质备份",
        "**启用两步验证（2FA）**，即使密码泄露也能保护账户",
        "**定期备份密码数据库**，防止数据丢失",
        "**不要在公共设备上保存密码**，使用完后清除浏览器数据",
        "**密码管理器本身也需要强主密码**，至少16位，包含多种字符类型"
    ]

    for reminder in reminders:
        st.markdown(f"""
        <div style="padding: 0.75rem; margin: 0.25rem 0; background-color: #fef3c7; 
                    border-radius: 6px; border-left: 4px solid #f59e0b;">
            {reminder}
        </div>
        """, unsafe_allow_html=True)



# ============================================================
# 页面：生成密码（原有功能，保持不变）
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
            mode_name = modes[parsed['mode']]
            
            # 根据模式动态显示建议文案
            if parsed['mode'] == AppState.MODE_RANDOM:
                st.write(f"**建议长度**: {parsed['length']} 位")
            else:
                # 口令密码和易记密码按单词数生成
                words_count = parsed['length'] // 4 if parsed['mode'] == AppState.MODE_PASSPHRASE else parsed['length'] // 5
                words_count = max(2, min(6, words_count))  # 限制在合理范围
                st.write(f"**建议单词数**: {words_count} 个")
            
            st.write(f"**建议模式**: {mode_name}")

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

        col_g1, col_g2, col_g3, col_g4 = st.columns(4)

        with col_g1:
            st.caption("👆 悬停密码框点击右上角复制")

        with col_g2:
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

        with col_g4:
            mode_names = ["随机密码", "口令密码", "易记密码"]
            download_content = f"""智能密码安全助手 - 密码导出

生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
生成模式: {mode_names[result_mode]}
密码长度: {len(pwd)} 位
强度评分: {eval_res.get('score', 'N/A')}/100 ({eval_res.get('level', '未知')})
熵值: {entropy:.1f} bits

⚠️ 安全提醒: 请妥善保管此密码，不要在不安全的环境中存储或传输。
建议将此密码保存到密码管理器（如 Bitwarden、1Password）中。

密码内容:
{pwd}
"""
            st.download_button(
                label="📥 下载密码",
                data=download_content,
                file_name=f"密码_{mode_names[result_mode]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True,
                key="btn_download_gen"
            )

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

        # 生成后引导保存
        st.divider()
        st.info("💡 生成强密码后，建议使用密码管理器安全保存")
        if st.button("💾 查看保存指南", key="btn_goto_manager"):
            AppState.set('current_page', AppState.PAGE_MANAGER)
            st.rerun()


# ============================================================
# 页面：安全指南（原有功能，保持不变）
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