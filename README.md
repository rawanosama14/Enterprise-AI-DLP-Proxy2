# 🛡️ Enterprise AI Security Proxy & DLP

An autonomous multi-agent guardrail and Data Loss Prevention (DLP) system designed to secure Large Language Model (LLM) workflows with real-time privacy sanitization, PII entity masking, and RAG policy auditing[cite: 4, 5]. Built with Python and Streamlit[cite: 5].

---

## 🚀 Key Features
- **Real-Time PII & Sensitive Entity Masking:** Automatically detects and redacts sensitive information (e.g., Medical IDs, SSNs, Emails, API keys, and names)[cite: 8].
- **Interactive Dark Glassmorphism UI:** Built with Streamlit[cite: 5] to provide an executive dashboard with telemetry metrics, risk scores, and execution times[cite: 5].
- **Circuit Breaker & Failover Control:** Includes robust self-healing and failover handling for latency timeouts and service exceptions[cite: 4, 8].
- **Simulation Mode Control:** Test various scenarios interactively (Normal Operation, Latency Timeouts, Masking Leaks, and System Crashes)[cite: 5].
- **RAG Security Policy Engine:** Audits prompts and outputs against enterprise security compliance rules[cite: 4, 8].

---

## 🛠️ Tech Stack
- **Python** 🐍
- **Streamlit** (Interactive Dashboard UI)[cite: 5]
- **Regex & NLP-based PII Detection**[cite: 8]
- **Custom CSS & Glassmorphism Design**[cite: 5]

---

## 📂 Project Structure
```text
📦 Enterprise-AI-DLP-Proxy
 ┣ 📜 app.py               # Main Streamlit dashboard application[cite: 5]
 ┣ 📜 dlp_system.py        # Core DLP pipeline & security logic[cite: 8]
 ┣ 📜 config.py            # Global configuration & risk thresholds[cite: 7]
 ┣ 📜 fine_tuned_model.py  # Context-aware PII detection engine[cite: 9]
 ┗ 📜 pre_filter.py        # Layer-1 secret & credential pre-filter[cite: 10]
⚙️ Installation & Running Locally
Clone the repository:

Bash
git clone [https://github.com/rawanosama14/Enterprise-AI-DLP-Proxy.git](https://github.com/rawanosama14/Enterprise-AI-DLP-Proxy.git)
cd Enterprise-AI-DLP-Proxy
Install dependencies:

Bash
pip install streamlit
Run the application:

Bash
streamlit run app.py
