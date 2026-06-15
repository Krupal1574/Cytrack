# 🛡️ CyTrack

<p align="center">
  <b>Monitor, Visualize, and Understand Global Cyber Threats</b>
</p>

<p align="center">
  A modern cybersecurity dashboard built with Django that provides threat intelligence, attack visualizations, and global cybercrime insights in one place.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Django-6.0-success?logo=django" />
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
  <img src="https://img.shields.io/badge/Status-Active-success" />
</p>

---

## 📖 Overview

CyTrack helps users explore cybersecurity data through interactive dashboards, visual analytics, and threat intelligence feeds.

Whether you're a student, researcher, security enthusiast, or analyst, CyTrack makes cyber threat information easier to understand and track.

---

## ✨ Features

* 🌍 Interactive global cybercrime heatmap
* 📈 Cyber attack trend analysis
* 📰 Latest cybersecurity news and intelligence
* 📊 Data-driven visualizations and charts
* 🔒 Secure environment variable management
* 🎨 Clean and responsive user interface

---

## 📸 Preview

Add screenshots here after deployment.

```text id="stphf9"
assets/
├── home.png
├── dashboard.png
└── heatmap.png
```

Example:

```md id="tm3bl4"
![Dashboard](assets/dashboard.png)
```

---

## 🛠️ Technology Stack

| Technology          | Purpose               |
| ------------------- | --------------------- |
| Django              | Backend Framework     |
| SQLite / PostgreSQL | Database              |
| Folium              | Interactive Maps      |
| Requests            | API Integration       |
| Python Dotenv       | Environment Variables |
| HTML/CSS/JavaScript | Frontend              |

---

## 📂 Project Structure

```text id="c47gzj"
CyTrack/
│
├── cyber/                 # Django project configuration
├── dashboard/             # Main application
├── static/                # CSS, images, charts
├── templates/             # HTML templates
├── manage.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash id="jkluxf"
git clone https://github.com/Krupal1574/Cytrack.git
cd Cytrack
```

### 2. Create a Virtual Environment

```bash id="a5b9ie"
python -m venv venv
```

Activate it:

**Windows**

```bash id="j76q0z"
venv\Scripts\activate
```

**Linux/macOS**

```bash id="jmvk5n"
source venv/bin/activate
```

### 3. Install Dependencies

```bash id="w3c8z2"
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file:

```env id="3dxmga"
OTX_API_KEY=your_api_key_here
```

---

### 5. Apply Database Migrations

```bash id="pzk56l"
python manage.py migrate
```

---

### 6. Run the Development Server

```bash id="v11suh"
python manage.py runserver
```

Open your browser:

```text id="u9hhfx"
http://127.0.0.1:8000
```

---

## ⚙️ Configuration

### Database

SQLite works out of the box.

To use PostgreSQL, update the database configuration inside:

```text id="7d39yk"
cyber/settings.py
```

---

### Environment Variables

Never commit secrets to GitHub.

Example:

```env id="i7h5gk"
OTX_API_KEY=your_api_key_here
DEBUG=False
SECRET_KEY=your_secret_key
```

---

## 🌐 Deployment

CyTrack can be deployed on:

* Render (Recommended)
* Railway
* PythonAnywhere
* VPS (Gunicorn + Nginx)

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Push your branch
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Krupal Prajapati**

* GitHub: https://github.com/Krupal1574

---

<p align="center">
  Built with Django • Cybersecurity • Open Source
</p>
