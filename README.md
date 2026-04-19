# NoSQL Dumper & VulnBlog

A comprehensive security research project developed for a graduation thesis at **Yildiz Technical University**. This project explores the detection and automation of **Time-Based Blind NoSQL Injection** vulnerabilities in MongoDB-based web applications.

## 📌 Project Overview

The project consists of two primary components:
1. **VulnBlog**: A deliberately vulnerable blog platform built with Flask and MongoDB to serve as a controlled lab environment.
2. **NoSQL Dumper**: A modular Python-based security tool designed to identify and exploit NoSQL injection vectors, specifically focusing on blind data exfiltration via server response time analysis.

## 🛠️ Features

### VulnBlog (Target)
* **User Management**: Registration, login, and profile management.
* **Flawed Sanitization**: Implements weak blacklists for `$where` that can be bypassed using logical operators like `$ne` or `$regex`.
* **Global Search Architecture Flaw**: A search bar that blindly queries both `blogs` and `users` collections, enabling cross-collection injection.

### NoSQL Dumper (Exploitation Tool)
* **Multi-Pattern Detection**: Iteratively tests for `sleep()`, `busy-wait` loops, and heavy `computation` to bypass keyword-based filters.
* **Statistical Analysis Engine**: Uses a "Baseline + Threshold" algorithm to eliminate false positives caused by network jitter.
* **Dynamic Exfiltration**: Extractor that dumps database content character-by-character using an automated exclusion-list strategy.
* **Modular Architecture**: Separated into `core` logic, `payloads` library, and `utils` for network communication.

## 🚀 Getting Started

### Hardware & Software Requirements
* **OS**: Windows 11 (Development environment).
* **Python**: 3.10+.
* **Database**: MongoDB Community Server.

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/coduronin/GradProject/.git](https://github.com/coduronin/GradProject.git)
   cd nosqli
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the MongoDB service:
   ```powershell
   Start-Service -Name "MongoDB"
   ```

## 📖 Usage Examples

### Running the Vulnerable App
```bash
python app.py
```

### Scanning for Vulnerabilities
Use the `--time-based` flag to trigger the statistical analysis engine:
```bash
python nosql_injector.py -u "http://localhost:5001/search" -p "q" --time-based
```

### Data Exfiltration
When a vulnerability is detected, the tool provides an interactive prompt to begin dumping the database:
```bash
python nosql_injector.py -u "http://localhost:5001/search" -p "q" -C "Cookie: session=..." --time-based -v
```

## 🛡️ Mitigation Strategies
To secure applications against the attacks demonstrated here:
* **Disable JavaScript**: Set `security.javascriptEnabled: false` in MongoDB config.
* **Use ODMs**: Utilize libraries like MongoEngine to ensure type-safe query construction.
* **Input Sanitization**: Avoid using `json.loads()` on untrusted input.

---
**Advisor**: Prof. Dr. Ayla ŞAYLI  
**Author**: Izzat Mammadzada
```
