"""Synthetic five-host dataset for developing the attack-path module offline.

All vulnerability and exploitability values in this file are illustrative only.
They are not findings from the real VMware lab.
"""

HOSTS = [
    {
        "host_id": "H1",
        "hostname": "Attacker Workstation",
        "ip_address": "10.10.0.10",
        "role": "entry_point",
        "criticality": "low",
    },
    {
        "host_id": "H2",
        "hostname": "Legacy Web Server",
        "ip_address": "10.10.0.20",
        "role": "web_server",
        "criticality": "medium",
    },
    {
        "host_id": "H3",
        "hostname": "Application Server",
        "ip_address": "10.10.0.30",
        "role": "application_server",
        "criticality": "high",
    },
    {
        "host_id": "H4",
        "hostname": "Internal File Server",
        "ip_address": "10.10.0.40",
        "role": "file_server",
        "criticality": "high",
    },
    {
        "host_id": "H5",
        "hostname": "Customer Database",
        "ip_address": "10.10.0.50",
        "role": "critical_database",
        "criticality": "critical",
    },
]

# exploitability and evidence_confidence are factors between 0.0 and 1.0.
# CVSS uses its standard 0.0-10.0 scale.
VULNERABILITIES = [
    {
        "vulnerability_id": "V-101",
        "host_id": "H2",
        "name": "Outdated web service",
        "cvss": 9.8,
        "exploitability": 0.90,
        "evidence_confidence": 0.90,
        "verification_status": "hypothetical",
    },
    {
        "vulnerability_id": "V-102",
        "host_id": "H3",
        "name": "Weak application configuration",
        "cvss": 8.1,
        "exploitability": 0.80,
        "evidence_confidence": 0.85,
        "verification_status": "hypothetical",
    },
    {
        "vulnerability_id": "V-103",
        "host_id": "H5",
        "name": "Database service weakness",
        "cvss": 9.1,
        "exploitability": 0.70,
        "evidence_confidence": 0.65,
        "verification_status": "hypothetical",
    },
    {
        "vulnerability_id": "V-104",
        "host_id": "H4",
        "name": "Exposed file-sharing service",
        "cvss": 7.5,
        "exploitability": 0.65,
        "evidence_confidence": 0.80,
        "verification_status": "hypothetical",
    },
    {
        "vulnerability_id": "V-105",
        "host_id": "H5",
        "name": "Weak database access control",
        "cvss": 8.8,
        "exploitability": 0.85,
        "evidence_confidence": 0.90,
        "verification_status": "hypothetical",
    },
    {
        "vulnerability_id": "V-106",
        "host_id": "H4",
        "name": "Outdated internal service",
        "cvss": 6.5,
        "exploitability": 0.55,
        "evidence_confidence": 0.75,
        "verification_status": "hypothetical",
    },
    {
        "vulnerability_id": "V-107",
        "host_id": "H4",
        "name": "Insufficient application-to-file-server isolation",
        "cvss": 6.1,
        "exploitability": 0.45,
        "evidence_confidence": 0.70,
        "verification_status": "hypothetical",
    },
]

# Each edge represents a possible attacker transition from source to target
# using the referenced vulnerability on the target host.
EDGES = [
    {
        "edge_id": "E-01",
        "source_host": "H1",
        "target_host": "H2",
        "vulnerability_id": "V-101",
        "reachable": True,
        "reachability_factor": 1.00,
        "validation_status": "hypothetical",
        "evidence": "Synthetic sample: source can reach the web server",
    },
    {
        "edge_id": "E-02",
        "source_host": "H2",
        "target_host": "H3",
        "vulnerability_id": "V-102",
        "reachable": True,
        "reachability_factor": 0.95,
        "validation_status": "hypothetical",
        "evidence": "Synthetic sample: web-to-application access",
    },
    {
        "edge_id": "E-03",
        "source_host": "H3",
        "target_host": "H5",
        "vulnerability_id": "V-103",
        "reachable": True,
        "reachability_factor": 0.90,
        "validation_status": "hypothetical",
        "evidence": "Synthetic sample: application-to-database access",
    },
    {
        "edge_id": "E-04",
        "source_host": "H1",
        "target_host": "H4",
        "vulnerability_id": "V-104",
        "reachable": True,
        "reachability_factor": 1.00,
        "validation_status": "hypothetical",
        "evidence": "Synthetic sample: source can reach the file server",
    },
    {
        "edge_id": "E-05",
        "source_host": "H4",
        "target_host": "H5",
        "vulnerability_id": "V-105",
        "reachable": True,
        "reachability_factor": 1.00,
        "validation_status": "hypothetical",
        "evidence": "Synthetic sample: file-server-to-database access",
    },
    {
        "edge_id": "E-06",
        "source_host": "H2",
        "target_host": "H4",
        "vulnerability_id": "V-106",
        "reachable": True,
        "reachability_factor": 0.90,
        "validation_status": "hypothetical",
        "evidence": "Synthetic sample: web-to-file-server access",
    },
    {
        "edge_id": "E-07",
        "source_host": "H3",
        "target_host": "H4",
        "vulnerability_id": "V-107",
        "reachable": True,
        "reachability_factor": 0.85,
        "validation_status": "hypothetical",
        "evidence": "Synthetic sample: application-to-file-server access",
    },
]

ENTRY_POINT = "H1"
CRITICAL_ASSET = "H5"
