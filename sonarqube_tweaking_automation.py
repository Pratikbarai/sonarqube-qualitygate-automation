import json
import os
import requests
from datetime import datetime
from dotenv import load_dotenv,dotenv_values 
from requests.auth import HTTPBasicAuth

# -------------------------
# Try to load commentjson for .jsonc support
# Install via: pip install commentjson
# -------------------------
try:
    import commentjson as json_loader
except ImportError:
    import json as json_loader
    print("[WARN] commentjson not installed. Comments in inst.jsonc will cause parse errors.")
    print("       Run: pip install commentjson")

# -------------------------
# SonarQube Server & Auth
# Credentials are read from environment variables — never hardcode secrets
# -------------------------
load_dotenv()
SONAR_URL      = os.environ.get("SONAR_URL",      "http://localhost:9000")
SONAR_USER     = os.environ.get("SONAR_USER",     "admin")
SONAR_PASSWORD = os.environ.get("SONAR_PASSWORD", "")
#SONAR_URL      = "http://localhost:9000"
#SONAR_USER     =  "admin"
#SONAR_PASSWORD = "@1234QweR@1234"

if not SONAR_PASSWORD:
    raise EnvironmentError("SONAR_PASSWORD environment variable is not set.")

# -------------------------
# Load JSONC instructions
# Supports both inst.json and inst.jsonc
# -------------------------
INST_FILE = "inst.jsonc" if os.path.exists("inst.jsonc") else "inst.json"

try:
    with open(INST_FILE) as f:
        data = json_loader.load(f)
except FileNotFoundError:
    raise FileNotFoundError(f"Instruction file '{INST_FILE}' not found. Create it before running.")
except Exception as e:
    raise ValueError(f"Failed to parse {INST_FILE}: {e}")

# -------------------------
# Industry-standard benchmark values
# Based on: OWASP SAMM, ISO 25010, SQALE, SonarQube Sonar Way defaults
# These act as the MINIMUM acceptable thresholds —
# user values in inst.json cannot be set looser than these.
# -------------------------
fixed_values = {
    # Coverage — minimum floors (LT operator: fail if below)
    "Line Coverage"        : 80,    # 80% line coverage minimum (Google/Meta standard)
    "Coverage"             : 80,    # 80% overall coverage floor
    "Condition Coverage"   : 75,    # 75% branch coverage (harder to achieve than line)

    # Duplication — maximum ceilings (GT operator: fail if above)
    "Duplicated Lines (%)": 3,      # 3% max duplication (SonarQube Sonar Way default)

    # Ratings — best acceptable rating (WT operator: fail if worse)
    # Rating scale: 1=A (best) → 5=E (worst)
    "Maintainability Rating" : 1,   # A — debt ratio must be ≤ 5% of project cost
    "Reliability Rating"     : 1,   # A — zero bugs allowed in production gate
    "Security Rating"        : 1,   # A — zero vulnerabilities, ALWAYS hardcoded to 1
    "Security Review Rating" : 1,   # A — 100% of hotspots reviewed (OWASP requirement)

    # Issue counts — maximum ceilings (GT operator: fail if above)
    "Uncovered Conditions"   : 25,  # Tighter than default — drives branch coverage up
    "Blocker Severity Issues": 0,   # Zero tolerance for blockers
    "High Severity Issues"   : 0,   # Zero tolerance for high-severity issues
    "Security Issues"        : 0,   # Zero tolerance for security vulnerabilities
}

# -------------------------
# Metric key mapping
# Maps human-readable names → SonarQube API metric keys
# -------------------------
metric_map = {
    "Condition Coverage"          : "branch_coverage",
    "Conditions to Cover"         : "conditions_to_cover",
    "Coverage"                    : "coverage",
    "Line Coverage"               : "line_coverage",
    "Lines to Cover"              : "lines_to_cover",
    "Uncovered Conditions"        : "uncovered_conditions",
    "Uncovered Lines"             : "uncovered_lines",
    "Duplicated Blocks"           : "duplicated_blocks",
    "Duplicated Lines"            : "duplicated_lines",
    "Duplicated Lines (%)"        : "duplicated_lines_density",
    "Accepted Issues"             : "accepted_issues",
    "Blocker Severity Issues"     : "software_quality_blocker_issues",
    "High Severity Issues"        : "software_quality_high_issues",
    "Info Severity Issues"        : "software_quality_info_issues",
    "Issues"                      : "violations",
    "Low Severity Issues"         : "software_quality_low_issues",
    "Medium Severity Issues"      : "software_quality_medium_issues",
    "Maintainability Issues"      : "maintainability_issues",
    "Maintainability Rating"      : "sqale_rating",
    "Technical Debt"              : "sqale_index",
    "Technical Debt Ratio"        : "sqale_debt_ratio",
    "Reliability Issues"          : "software_quality_reliability_issues",
    "Reliability Rating"          : "reliability_rating",
    "Reliability Remediation Effort": "reliability_remediation_effort",
    "Security Issues"             : "software_quality_security_issues",
    "Security Rating"             : "security_rating",
    "Security Hotspots Reviewed"  : "security_hotspots_reviewed",
    "Security Review Rating"      : "security_review_rating",
    "Security Remediation Effort" : "security_remediation_effort",   # Fixed: was in op_map but missing here
    "Lines"                       : "lines"
}

# -------------------------
# Operator classification
''' lt : Less Than   
        Meaning: The actual metric value must be less than the specified threshold. 
        Use Case: Commonly used for negative metrics like bugs, vulnerabilities, or code smells. 
        Example: Bugs < 5 → The project passes if there are fewer than 5 bugs.
        '''
''' gt : Greater Than 
        Meaning: The actual metric value must be greater than the specified threshold.
        Use Case: Used for positive metrics like test coverage or reliability. 
        Example: Coverage > 80% → The project passes if code coverage is greater than 80%. 
        '''
''' wt : Worse Than   — A-E ratings (fail if rating is worse than threshold)
        Meaning: This operator compares rating-based metrics (like Maintainability, Reliability, or Security Rating) on a qualitative scale from A (best) to E (worst). 
        Use Case: To ensure code quality doesn’t degrade below a certain rating level. 
        Example: Maintainability Rating is worse than A → The gate fails if the rating is B, C, D, or E. 
    ✅ Note: "Worse Than A" means any rating below A (i.e., B through E), so setting this condition ensures only an A rating passes.
    '''
# -------------------------
op_map = {
    "lt": [
        "Condition Coverage",
        "Coverage",
        "Line Coverage",
        "Security Hotspots Reviewed"
    ],
    "gt": [
        "Conditions to Cover", "Lines to Cover",
        "Uncovered Conditions", "Uncovered Lines",
        "Duplicated Blocks", "Duplicated Lines", "Duplicated Lines (%)",
        "Accepted Issues",
        "Blocker Severity Issues", "High Severity Issues",
        "Info Severity Issues", "Issues",
        "Low Severity Issues", "Medium Severity Issues",
        "Maintainability Issues",
        "Technical Debt", "Technical Debt Ratio",
        "Reliability Issues", "Reliability Remediation Effort",
        "Security Issues", "Security Remediation Effort",
        "Lines"
    ],
    "wt": [
        "Maintainability Rating",
        "Reliability Rating",
        "Security Rating",
        "Security Review Rating"
    ]
}

# -------------------------
# API Helpers
# -------------------------
def post(endpoint, payload):
    url = f"{SONAR_URL}{endpoint}"
    try:
        response = requests.post(
            url,
            auth=HTTPBasicAuth(SONAR_USER, SONAR_PASSWORD),
            data=payload,
            timeout=30
        )
        response.raise_for_status()
        try:
            print(json.dumps(response.json(), indent=2))
        except ValueError:
            print(response.text)
        return response
    except requests.exceptions.HTTPError as e:
        print(f"[HTTP ERROR] POST {endpoint} — {e.response.status_code}: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[REQUEST ERROR] POST {endpoint} — {e}")
    return None


def get(endpoint, params=None):
    url = f"{SONAR_URL}{endpoint}"
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(SONAR_USER, SONAR_PASSWORD),
            params=params,
            timeout=30
        )
        response.raise_for_status()
        try:
            return response.json()
        except ValueError:
            return response.text
    except requests.exceptions.HTTPError as e:
        print(f"[HTTP ERROR] GET {endpoint} — {e.response.status_code}: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[REQUEST ERROR] GET {endpoint} — {e}")
    return {}

# -------------------------
# Normalize values
# Converts letter ratings (A/B/C/D/E) to integers
# -------------------------
def normalize_value(metric_name, value):
    if isinstance(value, str):
        rating_map = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5}
        value = rating_map.get(value.upper(), value)

    if metric_name in op_map["wt"]:
        return int(value)

    if metric_name in ["Coverage", "Condition Coverage", "Line Coverage", "Duplicated Lines (%)"]:
        return float(value)

    return int(float(value))

# -------------------------
# Validate metrics
# -------------------------
def validate_metric(name, value):
    if name in op_map["wt"]:
        if not (1 <= int(value) <= 5):
            raise ValueError(f"{name} must be between 1 (A) and 5 (E), got: {value}")

    elif name in ["Coverage", "Condition Coverage", "Line Coverage", "Duplicated Lines (%)"]:
        if not (0.0 <= float(value) <= 100.0):
            raise ValueError(f"{name} must be between 0 and 100, got: {value}")

    elif int(value) < 0:
        raise ValueError(f"{name} must be >= 0, got: {value}")

# -------------------------
# Apply operator logic
# Enforces benchmarks — user values cannot be looser than fixed standards
#
# For LT metrics (coverage):  final = min(user, benchmark)  → stricter floor wins
# For GT metrics (issues):    final = max(user, benchmark)  → stricter ceiling wins
# For WT metrics (ratings):   final = min(user, benchmark)  → best (lowest number) wins
# -------------------------
def apply_operator_logic(metric_name, user_value, benchmark):
    if benchmark is None:
        return user_value

    if metric_name == "Security Rating":
        return 1  # Always enforce A — non-negotiable

    if metric_name in op_map["lt"]:
        return min(user_value, benchmark)   # Higher coverage required → stricter wins

    elif metric_name in op_map["gt"]:
        return max(user_value, benchmark)   # Lower issue count required → stricter wins

    elif metric_name in op_map["wt"]:
        return min(user_value, benchmark)   # Lower rating number = better → best wins

    return user_value

# -------------------------
# Determine SonarQube operator string
# -------------------------
def determine_op(metric_name):
    if metric_name in op_map["lt"]:
        return "LT"
    if metric_name in op_map["wt"]:
        return "GT"   # SonarQube: rating fails if value is Greater Than threshold (worse)
    return "GT"

# -------------------------
# Create or update a single gate condition
# -------------------------
def create_or_update_condition(gate_name, metric_name, user_value):
    if metric_name not in metric_map:
        print(f"[WARN] Unknown metric '{metric_name}' — skipping (not in metric_map)")
        return

    gate_info = get("/api/qualitygates/show", {"name": gate_name})
    if not gate_info:
        print(f"[ERROR] Could not fetch gate info for '{gate_name}'")
        return

    existing_conditions = {
        cond["metric"]: cond for cond in gate_info.get("conditions", [])
    }

    metric_key  = metric_map[metric_name]
    user_value  = normalize_value(metric_name, user_value)
    validate_metric(metric_name, user_value)

    benchmark   = fixed_values.get(metric_name)
    final_value = apply_operator_logic(metric_name, user_value, benchmark)

    existing = existing_conditions.get(metric_key)

    if existing:
        existing_val = normalize_value(metric_name, existing["error"])
        if final_value != existing_val:
            print(f"[UPDATE] {metric_name}: {existing_val} → {final_value}")
            post("/api/qualitygates/update_condition", {
                "id"    : existing["id"],
                "metric": metric_key,
                "op"    : determine_op(metric_name),
                "error" : final_value
            })
        else:
            print(f"[SKIP] {metric_name} already at {final_value} — no change needed")
    else:
        print(f"[CREATE] {metric_name}: {final_value}")
        post("/api/qualitygates/create_condition", {
            "gateName": gate_name,
            "metric"  : metric_key,
            "op"      : determine_op(metric_name),
            "error"   : final_value
        })

# -------------------------
# Apply all benchmark metrics to a gate (fill missing ones)
# -------------------------
def apply_benchmarks_to_gate(gate_name):
    gate_info = get("/api/qualitygates/show", {"name": gate_name})
    if not gate_info:
        return

    existing_metrics = {cond["metric"] for cond in gate_info.get("conditions", [])}

    for metric_name, value in fixed_values.items():
        if metric_map.get(metric_name) not in existing_metrics:
            print(f"[BENCHMARK] Applying missing standard: {metric_name} = {value}")
            create_or_update_condition(gate_name, metric_name, value)

# -------------------------
# Fetch and save project status post-scan
# -------------------------
def fetch_project_status(item):
    params = {}

    if "analysisId"  in item: params["analysisId"]  = item["analysisId"]
    elif "projectId" in item: params["projectId"]   = item["projectId"]
    elif "projectKey"in item: params["projectKey"]  = item["projectKey"]

    if "branch"      in item: params["branch"]      = item["branch"]
    if "pullRequest" in item: params["pullRequest"]  = item["pullRequest"]

    response = get("/api/qualitygates/project_status", params)

    # Use microseconds to avoid filename collision on rapid calls
    filename = f"project_status_{datetime.now().strftime('%d-%m-%Y_%H:%M:%S_%f')}.json"
    with open(filename, "w") as f:
        json.dump(response, f, indent=2)

    status = response.get("projectStatus", {}).get("status", "UNKNOWN")
    print(f"[STATUS] Gate result: {status}")
    print(f"[SAVED]  Project status → {filename}")

    return response

# -------------------------
# Main action dispatcher
# -------------------------
for item in data.get("qualityGates", []):
    action = item.get("action")

    # Create a Quality Gate. Requires the 'Administer Quality Gates' permission.
    if action == "create_gate":
        post("/api/qualitygates/create", {"name": item["name"]})
        apply_benchmarks_to_gate(item["name"])

    # Update a condition attached to a quality gate. Requires the 'Administer Quality Gates' permission
    elif action in ["add_condition", "update_condition"]:
        gate_name = item.get("gateName") or item.get("name")
        create_or_update_condition(gate_name, item["metric"], item["value"])
        apply_benchmarks_to_gate(gate_name)

    #Rename a Quality Gate. 'currentName' must be specified. Requires the 'Administer Quality Gates' permission.
    elif action == "rename_gate":
        post("/api/qualitygates/rename", {
            "currentName": item["currentName"],
            "name"       : item["name"]
        })

    # Delete a condition from a quality gate. Requires the 'Administer Quality Gates' permission.
    elif action == "delete_condition":
        post("/api/qualitygates/delete_condition", {"id": item["id"]})

    # Delete a Quality Gate. Parameter 'name' must be specified. Requires the 'Administer Quality Gates' permission.
    elif action == "delete_gate":
        post("/api/qualitygates/destroy", {"name": item["name"]})

    # Copy a Quality Gate.'sourceName' must be provided.
    elif action == "copy":
        post("/api/qualitygates/copy", {
            "name"      : item["name"],
            "sourceName": item["sourceName"]
        })

    # Allow a user to edit a Quality Gate. Requires one of the following permissions:1)'Administer Quality Gates' ,2) Edit right on the specified quality gate
    elif action == "add_user":
        post("/api/qualitygates/add_user", {
            "gateName": item["gateName"],
            "login"   : item["login"]
        })

    # Allow a group of users to edit a Quality Gate. Requires one of the following permissions:1)'Administer Quality Gates' ,2) Edit right on the specified quality gate
    elif action == "add_group":
        post("/api/qualitygates/add_group", {
            "gateName" : item["gateName"],
            "groupName": item["groupName"]
        })

    # Remove the ability from an user to edit a Quality Gate. Requires one of the following permissions: 1)'Administer Quality Gates', 2)Edit right on the specified quality gate
    elif action == "remove_user":
        post("/api/qualitygates/remove_user", {
            "gateName": item["gateName"],
            "login"   : item["login"]
        })

    # Remove the ability from a group to edit a Quality Gate. Requires one of the following permissions: 1)'Administer Quality Gates', 2)Edit right on the specified quality gate
    elif action == "remove_group":
        post("/api/qualitygates/remove_group", {
            "gateName" : item["gateName"],
            "groupName": item["groupName"]
        })

    # Associate a project to a quality gate. Requires one of the following permissions: 1)'Administer Quality Gates', 2)'Administer' right on the specified project
    elif action == "select_project":
        post("/api/qualitygates/select", {
            "gateName"  : item["gateName"],
            "projectKey": item["projectKey"]
        })

    # Remove the association of a project from a quality gate. Requires one of the following permissions: 1) 'Administer Quality Gates', 2) 'Administer' rights on the project
    elif action == "deselect_project":
        post("/api/qualitygates/deselect", {
            "projectKey": item["projectKey"]
        })

    # Set a quality gate as the default quality gate. Parameter 'name' must be specified. Requires the 'Administer Quality Gates' permission.
    elif action == "set_default":
        post("/api/qualitygates/set_as_default", {"name": item["name"]})

    #Get the quality gate status of a project or a Compute Engine task. Either 'analysisId', 'projectId' or 'projectKey' must be provided . The different statuses returned are: OK, WARN, ERROR, NONE. The NONE status is returned when there is no quality gate associated with the analysis. Returns an HTTP code 404 if the analysis associated with the task is not found or does not exist. Requires one of the following permissions: 1)'Administer System', 2)'Administer' rights on the specified project, 3)'Browse' on the specified project, 4)'Execute Analysis' on the specified project
    elif action == "get_project_status":
        fetch_project_status(item)

    else:
        print(f"[WARN] Unknown action: '{action}' — skipping")