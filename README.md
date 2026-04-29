# 🚀 SonarQube Quality Gate Automation & Benchmark Enforcement

Automate and enforce enterprise-grade SonarQube Quality Gates using Python and the SonarQube REST API.

This project provides a security-focused automation framework for:
- Creating and managing Quality Gates
- Enforcing OWASP-aligned secure coding standards
- Applying benchmark-driven validation
- Preventing weak quality configurations
- Automating project quality governance

---

# 📌 Features

## ✅ Quality Gate Automation

Supports full lifecycle management of SonarQube Quality Gates:

- Create Quality Gates
- Update Conditions
- Delete Conditions
- Rename Gates
- Copy Gates
- Set Default Gate
- Assign Projects to Gates
- Remove Project Associations

---

## 🔐 Security-First Enforcement

Enforces enterprise security standards such as:

- Zero Blocker Issues
- Zero High Severity Issues
- Mandatory Security Rating = A
- Mandatory Security Review Rating = A

---

## 📊 Benchmark-Based Validation

The framework prevents users from applying weaker thresholds than predefined enterprise standards.

### Example

| Metric | User Value | Benchmark | Applied |
|---|---|---|---|
| Coverage | 60% | 80% | 80% |
| Security Rating | B | A | A |

---

## 🧠 Intelligent Operator Logic

Supports:
- Less Than (`LT`)
- Greater Than (`GT`)
- Worse Than (`WT`)

with automatic strictness enforcement.

---

## 📁 JSONC Configuration Support

Supports:
- `inst.json`
- `inst.jsonc`

with comment-enabled configuration parsing using `commentjson`.

---

## 🌐 SonarQube REST API Integration

Uses:
- HTTP Basic Authentication
- Secure environment variables
- API-based automation workflows

---

## 📄 Automated Quality Status Reporting

Fetches:
- Quality Gate Results
- Project Analysis Status
- JSON Snapshot Reports

---

# 🏗️ Project Structure

```bash
.
├── sonarqube_tweaking_automation.py
├── inst.json / inst.jsonc
├── .env
├── project_status_*.json
├── requirements.txt
├── .gitignore
└── README.md
```

---

# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/Pratikbarai/sonarqube-qualitygate-automation.git

cd sonarqube-qualitygate-automation
```

---

## 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔑 Environment Configuration

Create a `.env` file:

```env
SONAR_URL=http://localhost:9000
SONAR_USER=admin
SONAR_PASSWORD=your_password
```

---

# 📝 Configuration File

The script reads instructions from:
- `inst.json`
- or `inst.jsonc`

## Example Configuration

```json
{
  "qualityGates": [

    {
      "action": "create_gate",
      "name": "Enterprise Security Gate"
    },

    {
      "action": "add_condition",
      "gateName": "Enterprise Security Gate",
      "metric": "Coverage",
      "value": 85
    },

    {
      "action": "add_condition",
      "gateName": "Enterprise Security Gate",
      "metric": "Security Rating",
      "value": "A"
    }

  ]
}
```

---

# 🚀 Usage

```bash
python sonarqube_tweaking_automation.py
```

---

# 📌 Supported Actions

| Action | Description |
|---|---|
| `create_gate` | Create a Quality Gate |
| `add_condition` | Add a condition |
| `update_condition` | Update a condition |
| `rename_gate` | Rename a gate |
| `delete_condition` | Delete a condition |
| `delete_gate` | Delete a gate |
| `copy` | Copy a Quality Gate |
| `add_user` | Grant user permissions |
| `remove_user` | Remove user permissions |
| `add_group` | Add group permissions |
| `remove_group` | Remove group permissions |
| `select_project` | Assign project to gate |
| `deselect_project` | Remove project assignment |
| `set_default` | Set default gate |
| `get_project_status` | Fetch project quality status |

---

# 📊 Default Enterprise Benchmarks

## Coverage Standards

| Metric | Minimum |
|---|---|
| Coverage | 80% |
| Line Coverage | 80% |
| Condition Coverage | 75% |

---

## Security Standards

| Metric | Requirement |
|---|---|
| Security Rating | A |
| Security Review Rating | A |
| Security Issues | 0 |
| Blocker Severity Issues | 0 |
| High Severity Issues | 0 |

---

## Maintainability Standards

| Metric | Requirement |
|---|---|
| Maintainability Rating | A |
| Reliability Rating | A |
| Duplicated Lines (%) | ≤ 3% |

---

# 🔍 Validation Logic

The framework automatically applies stricter rules.

## Operator Rules

| Type | Logic |
|---|---|
| LT | Higher minimum wins |
| GT | Lower maximum wins |
| WT | Better rating wins |

---

# 🛡️ Security Features

- No hardcoded credentials
- `.env`-based secret management
- API timeout handling
- HTTP error handling
- Request exception protection
- Input validation
- Rating normalization
- Safe JSON parsing

---

# 📦 Example Output

```bash
[CREATE] Coverage: 80
[UPDATE] Security Rating: 2 → 1
[STATUS] Gate result: OK
[SAVED] Project status → project_status_29-04-2026_12:45:10.json
```

---

# 💼 Use Cases

- DevSecOps Automation
- CI/CD Quality Enforcement
- Enterprise Code Governance
- Secure SDLC Pipelines
- SonarQube Administration
- Compliance-Oriented Engineering

---

# 🔮 Future Enhancements

- GitHub Actions Integration
- Jenkins Pipeline Support
- Multi-Project Orchestration
- AI-Based Quality Recommendations
- Dashboard Visualization
- Kubernetes Deployment Support

---

# 👨‍💻 Author

## Pratik Barai

Cybersecurity | DevSecOps | Security Automation | AI-Assisted Engineering

### 🔗 LinkedIn
https://linkedin.com/in/pratik-barai-517437260

### 🔗 GitHub
https://github.com/Pratikbarai

---

# 📜 License

This project is intended for:
- Educational Use
- Research Purposes
- Enterprise Automation
- Secure Software Engineering Practices

Use responsibly in production environments.
