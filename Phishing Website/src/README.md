# 🔍 Machine Learning-Based Phishing Website Detection

A web application built with **Flask** and **Machine Learning** that detects **phishing websites** based on 30 extracted URL features such as SSL state, domain age, subdomain structure, and request patterns.  
The system predicts whether a given website is **legitimate** or **phishing** and provides human-readable reasoning behind each prediction.

---

## 🚀 Project Overview
- Machine-learning-based phishing detection  
- Safe URL-only analysis  
- Random Forest backend  
- Modern cyber-themed UI  

---

## ✨ Key Features
- ✅ URL-based phishing detection  
- ✅ Explainable predictions  
- ✅ 30-feature extraction system  
- ✅ Cyber-themed responsive UI  
- ✅ Auto URL normalization  
- ✅ Invalid input handling  
- ✅ Calibrated confidence score  

---

## 🛠 Additional Enhancements
### 🔗 URL Normalization  
- Converts partial URLs into correct format  

### 🛑 Invalid Input Filtering  
- Prevents random non-URL text  

### 📊 Confidence Calibration  
- Displays realistic model confidence  

### 🎨 UI Upgrade  
- Dim neon glow and centered layout  

---

## 🧩 System Architecture

```
User Input (URL)
        ↓
Feature Extraction (30 handcrafted URL-based features)
        ↓
Trained ML Model (Random Forest Classifier)
        ↓
Prediction (Phishing ⚠️ or Legitimate ✅)
        ↓
Explainable Reason Display (Top 3–4 reasons)
```

---

## 📁 Folder Structure

```
Phishing Website/
│
├── images/                         # Screenshots, model analysis visuals
│   ├── Model Evaluation Analysis/
│   └── Test Case Output Snapshots/
│
└── src/
    ├── static/                     # CSS, favicon, static assets
    ├── templates/                  # HTML files (index.html)
    ├── app.py                      # Flask web application
    ├── feature_extraction.py       # Feature extraction logic
    ├── model_training.py           # Model training script
    ├── rf_model.pkl                # Trained ML model
    ├── convert_arff_to_csv.py      # ARFF → CSV converter
    ├── Training Dataset.arff       # Original dataset
    ├── X_train.csv / X_test.csv    # Processed training/test data
    └── requirements.txt            # Dependencies
```

---

## ⚙️ Tech Stack

| Category | Technologies |
|-----------|--------------|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Backend** | Python (Flask Framework) |
| **Machine Learning** | scikit-learn, pandas, numpy |
| **Feature Processing** | tldextract, BeautifulSoup, requests, whois |
| **Model** | Random Forest Classifier |
| **Version Control** | Git & GitHub |
| **IDE** | PyCharm |

---

## 🧠 Dataset & Model

- **Dataset:** *Training Dataset.arff* (converted to CSV using `convert_arff_to_csv.py`)  
- **Features:** 30 extracted features (e.g., `SSLfinal_State`, `having_Sub_Domain`, `age_of_domain`, etc.)  
- **Algorithm:** Random Forest Classifier  
- **Goal:** Predict whether a given website is **phishing (0)** or **legitimate (1)**  

---

## 🖥️ Running the Project Locally

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/phishing-website-detection.git
cd phishing-website-detection/src
```

### 2️⃣ Create Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate     # For Windows
# OR
source venv/bin/activate  # For Mac/Linux
```

### 3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 4️⃣ Run the Application
```bash
python app.py
```

### 5️⃣ Visit in Browser
Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🌐 Deployment

### 🔸 On GitHub Pages
(For static version only — UI preview)
- Move your `index.html` & `style.css` to `/docs`
- Enable GitHub Pages in repo settings → `/docs` branch.

---

## 📊 Example Output

| Input URL | Model Prediction | Explanation |
|------------|------------------|--------------|
| `http://secure-login-bank-update.com` | ⚠️ Phishing Website Detected | Missing SSL, suspicious keywords, short domain age |
| `https://www.google.com` | ✅ Legitimate Website | Proper SSL, long-term domain, indexed by Google |

---

## 🤝 Collaborators

| Name | Role |
|------|------|
| **Nabeel UrRehman** | Developer |
| **Syed Saad Ali** | Co-Developer |

---

## 📦 Requirements

```text
Flask
pandas
numpy
scikit-learn
tldextract
requests
beautifulsoup4
python-whois
gunicorn
```

---

## 🧾 License

This project is licensed under the **MIT License** — you’re free to use and modify it for educational or research purposes.

---

## 💡 Future Enhancements

- 🔐 Integrate live URL safety APIs (Google Safe Browsing, VirusTotal)
- 🧠 Include NLP-based feature extraction from webpage content
- 📊 Deploy dashboard for analytics of phishing trends
- ☁️ Cloud hosting and API integration for real-time detection

---

## 🏁 Acknowledgement

This project is developed as part of an academic research work on  
We sincerely extend our gratitude to all those who guided and supported us throughout the development of this project.
Our heartfelt thanks go to our faculty mentors and academic supervisors for their valuable insights, continuous encouragement, and expert feedback that shaped this research into a successful outcome.

We would also like to acknowledge the contributions of cybersecurity communities and open-source developers, whose collective efforts and tools inspired and empowered this work.

Finally, we thank our family, friends, and collaborators for their constant motivation and unwavering belief in our vision.

**“True innovation comes when passion meets purpose — and teamwork turns ideas into impact.”**
Inspired by real-world phishing defense mechanisms and modern web security standards.

---
## ⚠ Disclaimer
This tool is intended for *educational and research purposes only*.  
Predictions may not always be *100% accurate*.  
Use caution and verify suspicious websites manually.
---
> 💬 “Detecting phishing isn’t just about blocking fake sites — it’s about building smarter, safer web experiences.”
