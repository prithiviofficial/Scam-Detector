import hashlib
from pathlib import Path
import re

import joblib
import streamlit as st
from utils import clean

st.set_page_config(page_title="Scam Detector", page_icon="🛡️")

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #111827 55%, #172554 100%);
    }

footer {
        visibility: hidden;
    }
    
    .block-container {
        max-width: 1100px;
        padding: 2rem 2rem 4rem;
    }

    .hero {
        padding: 2.25rem 2.5rem;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(147, 197, 253, 0.25);
        border-radius: 24px;
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.95), rgba(30, 64, 175, 0.55));
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.25);
    }

    .hero h1 {
        margin: 0 0 0.75rem;
        color: #f8fafc;
        font-size: 2.6rem;
        line-height: 1.1;
    }

    .hero p {
        margin: 0;
        color: #cbd5e1;
        font-size: 1.05rem;
    }

    .eyebrow {
        color: #93c5fd;
        font-size: 0.75rem;
        font-weight: 800;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        margin-bottom: 0.75rem;
    }

    .hero-badge {
        display: inline-block;
        margin-top: 1.25rem;
        padding: 0.35rem 0.7rem;
        border: 1px solid rgba(147, 197, 253, 0.3);
        border-radius: 999px;
        color: #bfdbfe;
        background: rgba(15, 23, 42, 0.35);
        font-size: 0.8rem;
    }

    .section-label {
        color: #93c5fd;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        margin: 1.5rem 0 0.5rem;
    }

    div[data-testid="stTextArea"] textarea {
        border-radius: 14px;
        border: 1px solid #334155;
        background-color: #111827;
        color: #f8fafc;
        font-size: 1rem;
        line-height: 1.55;
    }

    div[data-testid="stTextArea"] label p,
    div[data-testid="stSelectbox"] label p {
        color: #cbd5e1;
        font-weight: 600;
    }

    div[data-testid="stButton"] > button {
        width: 100%;
        border: 0;
        border-radius: 12px;
        color: white;
        background: linear-gradient(90deg, #2563eb, #7c3aed);
        font-weight: 700;
        padding: 0.65rem 1rem;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }

    div[data-testid="stButton"] > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(37, 99, 235, 0.35);
        color: white;
    }

    .trust-note {
        color: #94a3b8;
        font-size: 0.85rem;
        text-align: center;
        margin-top: 1.5rem;
    }

    .result-card {
        padding: 1rem 1.25rem;
        border-radius: 16px;
        background: rgba(15, 23, 42, 0.55);
        border: 1px solid rgba(148, 163, 184, 0.18);
        margin: 0.75rem 0;
    }

    .result-card strong {
        color: #f8fafc;
    }

    .tip-card {
        height: 100%;
        padding: 1rem;
        border: 1px solid rgba(148, 163, 184, 0.16);
        border-radius: 14px;
        background: rgba(30, 41, 59, 0.45);
    }

    .tip-card p {
        color: #cbd5e1;
        font-size: 0.9rem;
        margin-bottom: 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

@st.cache_resource
def load_model():
    model_path = Path(__file__).resolve().parent / "model" / "scam_model.joblib"
    expected_sha256 = "60D2E9BACED0741397F9FA44E509358C508306A5BCD227D08A61BC6F04DA9BF3"

    if not model_path.is_file():
        raise FileNotFoundError(f"Model file was not found: {model_path}")

    actual_sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest().upper()
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            "Model integrity check failed. The model file may be corrupted or replaced."
        )

    return joblib.load(model_path)

model = load_model()

RED_FLAGS = {
    "Asks for money or a fee": r"registration fee|security deposit|processing fee|pay (a|the)? ?fee|send money|refundable",
    "Too-good-to-be-true earnings": r"earn \$?\d+|guaranteed (income|salary|job)|easy money|no experience (needed|required)",
    "Pushes you to chat on WhatsApp/Telegram": r"whatsapp|telegram",
    "Uses a free email address": r"@gmail\.com|@yahoo\.com|@outlook\.com",
    "Creates urgency": r"urgent|act now|limited (time|seats)|apply immediately|last chance",
    "Asks for sensitive details": r"otp|bank details|aadhaar|pan card|password|card number|kyc",
    "Prize or lottery claim": r"you have won|lottery|winner|claim your prize|free gift",
}

st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">AI-powered message safety</div>
        <h1>🛡️ Fake Job & Scam Message Detector</h1>
        <p>Analyze suspicious job posts, SMS messages, WhatsApp chats, and emails in seconds.</p>
        <div class="hero-badge">Private by design · No message is stored</div>
    </div>
    """,
    unsafe_allow_html=True,
)

examples = {
    "Choose an example...": "",
    "Fake job offer": "Work from home! Earn 50000 per month, no experience needed. Pay a registration fee of Rs 2000 to confirm your job. Contact us on WhatsApp now, limited seats!",
    "Prize scam SMS": "Congratulations! You have won a free gift voucher. Click http://claim-prize.xyz now to claim your prize. Urgent!",
    "Normal message": "Hi, the team meeting is moved to 3 pm tomorrow. Please bring the project report.",
}

analyze_tab, guide_tab = st.tabs(["🔍 Analyze a message", "💡 Stay scam-aware"])

with analyze_tab:
    left, right = st.columns([1, 2], gap="large")
    with left:
        st.markdown('<div class="section-label">1 · Use a sample</div>', unsafe_allow_html=True)
        choice = st.selectbox("Try a sample", list(examples.keys()))
        st.markdown(
            '<div class="tip-card"><strong>What can I check?</strong><p>Job offers, SMS, emails, social-media DMs, and payment requests.</p></div>',
            unsafe_allow_html=True,
        )
    with right:
        st.markdown('<div class="section-label">2 · Paste the message</div>', unsafe_allow_html=True)
        text = st.text_area(
            "Message or job posting",
            value=examples[choice],
            height=210,
            placeholder="Paste the suspicious message here...",
            label_visibility="visible",
        )
        st.caption(f"{len(text):,} characters · {len(text.split()):,} words")

    if st.button("🔍 Analyze message", type="primary"):
        if not text.strip():
            st.warning("Please paste some text first.")
        else:
            prob = float(model.predict_proba([clean(text)])[0][1])
            found = [name for name, pattern in RED_FLAGS.items() if re.search(pattern, text.lower())]
            st.markdown('<div class="section-label">Analysis result</div>', unsafe_allow_html=True)

            score_col, summary_col = st.columns([1, 2], gap="large")
            with score_col:
                st.metric("Scam risk score", f"{prob:.0%}")
                st.progress(prob)
            with summary_col:
                if prob >= 0.7:
                    st.error("🚨 High risk — do not pay, click links, or share personal details.")
                elif prob >= 0.4:
                    st.warning("⚠️ Suspicious — verify the sender and company independently.")
                else:
                    st.success("✅ Low risk signals — still use your normal online safety habits.")

            if found:
                st.markdown("#### Signals found in this message")
                signal_columns = st.columns(min(3, len(found)))
                for index, flag in enumerate(found):
                    with signal_columns[index % len(signal_columns)]:
                        st.markdown(f'<div class="result-card">🚩 <strong>{flag}</strong></div>', unsafe_allow_html=True)
            else:
                st.info("No common red-flag phrases were detected. A clean result is not a guarantee.")

            with st.expander("How should I respond?"):
                st.markdown(
                    "1. **Pause** — scammers create pressure so you act quickly.\n"
                    "2. **Verify** — contact the person or company through an official website.\n"
                    "3. **Protect yourself** — never share OTPs, passwords, card details, or upfront fees.\n"
                    "4. **Report it** — block the sender and report the account or message."
                )

with guide_tab:
    st.markdown('<div class="section-label">A quick safety checklist</div>', unsafe_allow_html=True)
    checklist = st.columns(3)
    tips = [
        ("💳 Never pay upfront", "Legitimate employers do not require registration, training, or security fees before hiring."),
        ("🔗 Inspect every link", "Check the domain carefully and avoid shortened links or unexpected attachments."),
        ("🔐 Keep secrets secret", "No genuine support agent needs your OTP, password, PIN, or full card number."),
    ]
    for column, (title, description) in zip(checklist, tips):
        with column:
            st.markdown(f'<div class="tip-card"><strong>{title}</strong><p>{description}</p></div>', unsafe_allow_html=True)
    st.markdown("#### What the score means")
    st.markdown(
        "- **0–39%:** Few scam-like patterns detected.\n"
        "- **40–69%:** Some suspicious patterns are present; verify before acting.\n"
        "- **70–100%:** Strong scam signals; stop engagement and report the message."
    )

st.markdown(
    '<div class="trust-note">Predictions are advisory, not proof. Always verify independently.</div>',
    unsafe_allow_html=True,
)
