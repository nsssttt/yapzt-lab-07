"""Recreate the lab 7 Taiga backlog from the adjacent CSV artifacts.

Set TAIGA_URL, TAIGA_USERNAME, and TAIGA_PASSWORD in the environment before
running. This script does not contain instance credentials.
"""

import csv
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


HERE = Path(__file__).resolve().parent
BASE_URL = os.environ.get("TAIGA_URL", "http://127.0.0.1:9009").rstrip("/")
USERNAME = os.environ.get("TAIGA_USERNAME")
PASSWORD = os.environ.get("TAIGA_PASSWORD")
if not USERNAME or not PASSWORD:
    raise SystemExit("Set TAIGA_USERNAME and TAIGA_PASSWORD in the environment.")

target = json.loads((HERE / "taiga_project.json").read_text(encoding="utf-8"))
API = BASE_URL + "/api/v1"


def api(method, path, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(data, ensure_ascii=False).encode("utf-8") if data is not None else None
    request = Request(API + path, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else None
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Taiga API returned HTTP {error.code} for {method} {path}: {detail[:500]}") from error


def tags_for(record):
    return [str(item[0] if isinstance(item, (list, tuple)) else item).upper() for item in record.get("tags", []) if item]


def rows(name):
    with (HERE / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


token = api("POST", "/auth", {"type": "normal", "username": USERNAME, "password": PASSWORD})["auth_token"]
try:
    project = api("GET", "/projects/by_slug?slug=" + quote(target["project_slug"]), token=token)
except RuntimeError as error:
    if "HTTP 404" not in str(error):
        raise
    project = api("POST", "/projects", {
        "name": target["project_name"],
        "description": "Sample task management project for software testing.",
        "is_backlog_activated": True,
        "is_issues_activated": True,
        "is_kanban_activated": True,
        "is_private": True,
        "is_wiki_activated": True,
    }, token)
project_id = project["id"]

test_cases = rows("test_cases.csv")
functional = rows("taiga_issues.csv")
nfr = rows("taiga_nfr_tasks.csv")
story_title = {row["Story_ID"]: row["Title"].removeprefix("Do ") for row in functional}
story_req = {}
for case in test_cases:
    if case["Story_ID"]:
        story_req.setdefault(case["Story_ID"], case["Requirement"])

stories = api("GET", f"/userstories?project={project_id}&page_size=100", token=token)
story_map = {tag: record for record in stories for tag in tags_for(record) if tag.startswith("US-")}
created_stories = {}
for number, story_tag in enumerate(sorted(story_title), 1):
    record = story_map.get(story_tag)
    if record is None:
        requirement = story_req.get(story_tag, "FR-001")
        record = api("POST", "/userstories", {
            "project": project_id,
            "subject": f"{story_tag} {story_title[story_tag]}",
            "description": f"Functional requirement {requirement}.",
            "backlog_order": number,
            "tags": [story_tag, requirement, "Sample"],
        }, token)
    created_stories[story_tag] = record

tasks = api("GET", f"/tasks?project={project_id}&page_size=100", token=token)
for number, row in enumerate(functional, 1):
    tag = row["Issue_ID"].upper()
    if any(tag in tags_for(task) for task in tasks):
        continue
    related = [case["Case_ID"] for case in test_cases if case["Story_ID"] == row["Story_ID"]]
    api("POST", "/tasks", {
        "project": project_id,
        "user_story": created_stories[row["Story_ID"]]["id"],
        "subject": row["Title"],
        "description": "Planned test cases: " + ", ".join(related),
        "us_order": number,
        "tags": [tag, row["Story_ID"], "TP-FUNC"],
    }, token)

for number, row in enumerate(nfr, 1):
    tag = row["Task_ID"].upper()
    if any(tag in tags_for(task) for task in tasks):
        continue
    api("POST", "/tasks", {
        "project": project_id,
        "subject": f"{tag}: {row['Title']}",
        "description": "Planned test cases: " + row["Case_IDs"].replace(";", ", "),
        "us_order": number,
        "tags": [tag, "TP-NFR", "Not run"],
    }, token)

types = api("GET", f"/issue-types?project={project_id}&page_size=100", token=token)
for number, (name, color) in enumerate([
    ("Functionality Test", "#4A90E2"), ("Usability Test", "#50C878"),
    ("Performance Test", "#F5A623"), ("Security Test", "#D0021B"),
    ("Integration Test", "#9013FE"), ("Reliability Test", "#7ED321"),
    ("Supportability Test", "#4A4A4A"),
], 4):
    if not any(item.get("name") == name for item in types):
        api("POST", "/issue-types", {"name": name, "color": color, "order": number, "project": project_id}, token)
fields = api("GET", f"/issue-custom-attributes?project={project_id}&page_size=100", token=token)
if not any(item.get("name") == "Link" for item in fields):
    api("POST", "/issue-custom-attributes", {"name": "Link", "description": "Link to a requirement, test case, or test run", "order": 1, "project": project_id}, token)

for slug, title, content in [
    ("test-documentation", "Test documentation", "Test documentation for functional, non-functional, regression, and smoke testing."),
    ("requirements-specification", "Requirements specification", "Functional and non-functional requirements are documented in the report."),
    ("user-stories", "User stories", "User stories are represented in the Taiga backlog."),
    ("non-functional-requirements", "Non-functional requirements", "Usability, responsiveness, recovery, and access control."),
    ("testing-process", "Testing process", "Plan tests, design cases, execute checks, record results, and report findings."),
    ("test-design-specification", "Test design", "Synthetic test cases are provided in test_cases.csv."),
    ("traceability-matrix", "Traceability matrix", "Relationships between requirements, stories, and cases are represented by the dataset."),
    ("test-report-template", "Test reports", "Record actual results after running the tests against your own application."),
]:
    current = api("GET", f"/wiki?project={project_id}&page_size=100", token=token)
    if not any(page.get("slug") == slug for page in current):
        api("POST", "/wiki", {"project": project_id, "slug": slug, "content": f"# {title}\n\n{content}"}, token)

print(f"Taiga project restored at {BASE_URL}/project/{project['slug']}/backlog")

