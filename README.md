# NoSQL Dumper & VulnBlog

[cite_start]A comprehensive security research project developed for a graduation thesis at **Yildiz Technical University**[cite: 4, 6]. [cite_start]This project explores the detection and automation of **Time-Based Blind NoSQL Injection** vulnerabilities in MongoDB-based web applications[cite: 24, 25].

## 📌 Project Overview

The project consists of two primary components:
1.  [cite_start]**VulnBlog**: A deliberately vulnerable blog platform built with Flask and MongoDB to serve as a controlled lab environment[cite: 27, 37].
2.  [cite_start]**NoSQL Dumper**: A modular Python-based security tool designed to identify and exploit NoSQL injection vectors, specifically focusing on blind data exfiltration via server response time analysis[cite: 28, 29, 38].

## 🛠️ Features

### VulnBlog (Target)
* [cite_start]**User Management**: Registration, login, and profile management[cite: 276, 447].
* [cite_start]**Flawed Sanitization**: Implements weak blacklists for `$where` that can be bypassed using logical operators like `$ne` or `$regex`[cite: 376, 377].
* [cite_start]**Global Search Architecture Flaw**: A search bar that blindly queries both `blogs` and `users` collections, enabling cross-collection injection[cite: 420, 422].

### NoSQL Dumper (Exploitation Tool)
* [cite_start]**Multi-Pattern Detection**: Iteratively tests for `sleep()`, `busy-wait` loops, and heavy `computation` to bypass keyword-based filters[cite: 608, 611].
* [cite_start]**Statistical Analysis Engine**: Uses a "Baseline + Threshold" algorithm to eliminate false positives caused by network jitter[cite: 646, 652].
* [cite_start]**Dynamic Exfiltration**: Extractor that dumps database content character-by-character using an automated exclusion-list strategy[cite: 745, 885].
* [cite_start]**Modular Architecture**: Separated into `core` logic, `payloads` library, and `utils` for network communication[cite: 598, 599].

## 🚀 Getting Started

### Hardware & Software Requirements
* [cite_start]**OS**: Windows 11 (Development environment)[cite: 78].
* [cite_start]**Python**: 3.10+[cite: 82].
* [cite_start]**Database**: MongoDB Community Server[cite: 188].

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/nosql-dumper.git](https://github.com/yourusername/nosql-dumper.git)
   cd nosql-dumper
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
[cite_start]When a vulnerability is detected, the tool provides an interactive prompt to begin dumping the database[cite: 830, 839]:
```bash
python nosql_injector.py -u "http://localhost:5001/search" -p "q" -C "Cookie: session=..." --time-based -v
```

## 🛡️ Mitigation Strategies
To secure applications against the attacks demonstrated here:
* [cite_start]**Disable JavaScript**: Set `security.javascriptEnabled: false` in MongoDB config[cite: 937].
* [cite_start]**Use ODMs**: Utilize libraries like MongoEngine to ensure type-safe query construction[cite: 936].
* [cite_start]**Input Sanitization**: Avoid using `json.loads()` on untrusted input[cite: 935].

---
[cite_start]**Advisor**: Prof. Dr. Ayla ŞAYLI [cite: 9]  
[cite_start]**Author**: Izzat Mammadzada [cite: 10]
```
