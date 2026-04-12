# PhishGuard 🛡️

PhishGuard is an AI-powered phishing detection system designed to protect users from malicious links, deceptive SMS messages, and fraudulent voice calls, specifically tailored for the Philippine context (e.g., GCash, BDO, PayMaya).

## 🚀 Features
- **URL Scanner**: analyzes links for homoglyph attacks, SSL status, and domain age.
- **SMS/Message Scanner**: uses Natural Language Processing (NLP) and Machine Learning (Logistic Regression) to identify scam patterns.
- **Voice Scanner**: transcribes and analyzes audio/vishing attempts using OpenAI Whisper.
- **Philippine Context**: trained to recognize threats targeting local PH financial services.
- **Scan History**: persistent dashboard to view past security reports.

---

## 🛠️ System Requirements
- **Node.js**: v18 or higher (for the frontend)
- **Python**: v3.9 or higher (for the backend)
- **MongoDB**: local instance or MongoDB Atlas account
- **Package Managers**: `pnpm` (frontend) and `pip` (backend)

---

## 📦 Installation Guide

### 1. Project Setup
Clone the repository and create your environment configuration:
```bash
# Copy the environment example to a local file
cp .env.example .env
```
*Update `.env` with your MongoDB connection string if you are not using a local default.*

### 2. Backend Setup (FastAPI)
```bash
cd backend

# Create a virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the backend server
python app.py
```
The backend will be running at `http://localhost:8000`.

### 3. Frontend Setup (Next.js)
Open a new terminal window:
```bash
# Navigate to the root directory
cd ..

# Install dependencies
pnpm install

# Start the development server
pnpm dev
```
The application will be accessible at `http://localhost:3000`.

---

## 🤖 Machine Learning Model
The system uses a **Hybrid Detection Engine**:
`Final Risk Score = (Rule-Based Heuristic + ML Probability) / 2`

The Machine Learning component uses:
- **Algorithm**: Logistic Regression
- **Vectorizer**: TF-IDF (Term Frequency-Inverse Document Frequency)
- **Library**: scikit-learn

If you need to retrain the model with fresh data, run:
```bash
cd backend
python train_model.py
```

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` (if available) for more information.

---

**Stay Safe Online! 🇵🇭**
