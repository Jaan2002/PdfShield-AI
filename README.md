# PDFShield AI 🛡️
## Automated Threat Alert System

PDFShield AI includes an automated email alert system integrated with Mailtrap.io.

When a malicious PDF is detected:
- The ML model identifies the threat
- Kestra orchestrates the workflow pipeline
- An automated alert email is triggered
- The threat notification is sent using Mailtrap.io SMTP service

This helps simulate real-world SOC (Security Operations Center) alerting workflows and automated incident response systems.

### Alert Includes
- File name
- Threat verdict
- Confidence score
- Detection timestamp
- Threat severity level

### Technologies Used
- Kestra Workflow Orchestration
- Mailtrap.io SMTP
- Flask API
- Python Email Automation

## 📂 Project Structure

```bash
pdfshield-ai/
│
├── screenshots/
├── frontend/
├── scanner/
├── model/
├── uploads/
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/PdfShield-AI.git
cd PdfShield-AI
```

---

## ▶️ Run with Docker

```bash
docker compose up --build
```

---

## 🌐 Access Application

Frontend:
```txt
http://localhost:5000
```

Kestra Dashboard:
```txt
http://localhost:8080
```

Scanner API:
```txt
http://localhost:5001
```

---

## 🧠 Machine Learning Workflow

1. Upload PDF file
2. Extract structural features
3. Analyze suspicious behaviors
4. Pass features to trained ML model
5. Predict:
   - Benign
   - Malicious
6. Display confidence score

---

## 🔒 Security Features

- PDF structural inspection
- JavaScript detection
- Embedded object analysis
- Entropy analysis
- Suspicious keyword detection

---

## 📸 Screenshots

### Workflow Topology / Architecture
<img width="1010" height="693" alt="topology-k" src="https://github.com/user-attachments/assets/a7335358-9e50-43a0-b3a7-d634b97225bb" />

### Kestra Workflow Result
<img width="1867" height="900" alt="kestra" src="https://github.com/user-attachments/assets/49b8324a-679f-4999-bb67-29f62f0dcf12" />

### PdfShield.Ai Dashboard
<img width="1918" height="905" alt="frontend" src="https://github.com/user-attachments/assets/749e547f-222b-46f3-a811-85baa0376ec7" />

### Automated Email Alert using Mailtrap.io
<img width="1876" height="872" alt="email-sent" src="https://github.com/user-attachments/assets/2fa46c11-7b71-4381-ae40-05f4b0ad2ada" />


---

## 📌 Future Improvements

- Deep Learning integration
- Real-time threat intelligence
- Multi-file batch scanning
- Email alert system
- Cloud deployment
- SIEM integration

---

## 👩‍💻 Author

Jaanvi Kapoor

Aspiring Software Developer & AI & Cybersecurity Enthusiast

---

## 📄 License

This project is for educational and research purposes.
