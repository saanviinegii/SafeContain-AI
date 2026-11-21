#!/usr/bin/env python3
"""Synthetic Enterprise Dataset Generator for SafeContain AI.

Generates 12 interconnected, mathematically consistent CSV datasets for enterprise
cyber defense, graph topology exploration, attack-path modeling, uncertainty evaluation,
response planning optimization, and business continuity simulation.
"""

import csv
import json
import os
import random
from datetime import datetime, timezone, timedelta

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_enterprise")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Fixed seed for deterministic, reproducible generation
random.seed(42)
BASE_TIME = datetime(2026, 11, 15, 8, 0, 0, tzinfo=timezone.utc)


def generate_all():
    print("Generating SafeContain AI Synthetic Enterprise Dataset...")

    # =========================================================================
    # 1. NODES (120 Nodes)
    # =========================================================================
    nodes = []

    # 1.1 USERS (30 Users)
    user_data = [
        ("usr-001", "node-user-marcus", "Marcus Vance", "marcus.vance", "Engineering", "Developer", "USER", "EMPLOYEE", 0.65, "COMPROMISED", "Senior Backend Engineer with access to payment repo"),
        ("usr-002", "node-user-sarah", "Sarah Chen", "sarah.chen", "DevOps", "DevOps Admin", "ADMIN", "EMPLOYEE", 0.85, "MONITORED", "Lead Cloud DevOps Administrator with root cloud access"),
        ("usr-003", "node-user-alex", "Alex Rivera", "alex.rivera", "Security", "SecOps Analyst", "ELEVATED", "EMPLOYEE", 0.70, "HEALTHY", "Tier-2 SOC Security Analyst"),
        ("usr-004", "node-user-elena", "Elena Rostova", "elena.rostova", "Finance", "Finance Director", "USER", "EMPLOYEE", 0.80, "HEALTHY", "Finance Operations Director approving payroll runs"),
        ("usr-005", "node-user-david", "David Kim", "david.kim", "Engineering", "Frontend Engineer", "USER", "EMPLOYEE", 0.40, "HEALTHY", "Web UI Frontend Engineer"),
        ("usr-006", "node-user-priya", "Priya Patel", "priya.patel", "Engineering", "Database Admin", "ADMIN", "EMPLOYEE", 0.90, "HEALTHY", "Principal DBA managing core SQL clusters"),
        ("usr-007", "node-user-james", "James Wilson", "james.wilson", "IT Support", "IT Helpdesk", "ELEVATED", "EMPLOYEE", 0.60, "HEALTHY", "IT Support Engineer with local admin rights"),
        ("usr-008", "node-user-rachel", "Rachel Adams", "rachel.adams", "Executive", "CISO", "ADMIN", "EMPLOYEE", 0.95, "HEALTHY", "Chief Information Security Officer"),
        ("usr-009", "node-user-liam", "Liam O'Connor", "liam.oconnor", "HR", "HR Specialist", "USER", "EMPLOYEE", 0.50, "HEALTHY", "HR Specialist managing employee records"),
        ("usr-010", "node-user-tom", "Tom Hardy", "tom.hardy", "Contractor", "External QA Tester", "USER", "CONTRACTOR", 0.45, "SUSPECTED", "Third-party QA contractor testing staging APIs"),
        ("usr-011", "node-user-svc-cicd", "svc-cicd-pipeline", "svc_cicd_pipeline", "DevOps", "Service Account", "ADMIN", "SERVICE_ACCOUNT", 0.85, "MONITORED", "GitLab CI/CD automated deployment runner"),
        ("usr-012", "node-user-svc-backup", "svc-backup-daemon", "svc_backup_daemon", "IT Operations", "Service Account", "ELEVATED", "SERVICE_ACCOUNT", 0.80, "HEALTHY", "Automated nightly backup service account"),
        ("usr-013", "node-user-svc-payment", "svc-payment-broker", "svc_payment_broker", "Payments", "Service Account", "ADMIN", "SERVICE_ACCOUNT", 0.95, "MONITORED", "Microservice payment processing service account"),
        ("usr-014", "node-user-svc-siem", "svc-splunk-forwarder", "svc_splunk_forwarder", "Security", "Service Account", "USER", "SERVICE_ACCOUNT", 0.70, "HEALTHY", "Telemetry ingestion daemon for SIEM forwarders"),
        ("usr-015", "node-user-svc-scan", "svc-vuln-scanner", "svc_vuln_scanner", "Security", "Service Account", "ELEVATED", "SERVICE_ACCOUNT", 0.75, "HEALTHY", "Vulnerability vulnerability audit scanner account"),
        ("usr-016", "node-user-claire", "Claire Dupont", "claire.dupont", "Legal", "Compliance Counsel", "USER", "EMPLOYEE", 0.65, "HEALTHY", "Corporate Regulatory & Privacy Counsel"),
        ("usr-017", "node-user-ahmed", "Ahmed Mansour", "ahmed.mansour", "Engineering", "SecOps Architect", "ADMIN", "EMPLOYEE", 0.85, "HEALTHY", "Application Security Architect"),
        ("usr-018", "node-user-kevin", "Kevin Novak", "kevin.novak", "Operations", "SRE Lead", "ADMIN", "EMPLOYEE", 0.85, "HEALTHY", "Site Reliability Engineering Lead"),
        ("usr-019", "node-user-chloe", "Chloe Martin", "chloe.martin", "Marketing", "Brand Specialist", "USER", "EMPLOYEE", 0.30, "HEALTHY", "Marketing Brand Content Specialist"),
        ("usr-020", "node-user-zack", "Zack Taylor", "zack.taylor", "Contractor", "Penetration Tester", "ADMIN", "CONTRACTOR", 0.75, "MONITORED", "Authorized external red-team contractor"),
        ("usr-021", "node-user-maya", "Maya Lin", "maya.lin", "Engineering", "Payment Architect", "ADMIN", "EMPLOYEE", 0.90, "HEALTHY", "Lead Architect for Citizen Payment Gateway"),
        ("usr-022", "node-user-sam", "Samira Khan", "samira.khan", "Finance", "Treasury Analyst", "USER", "EMPLOYEE", 0.70, "HEALTHY", "Treasury and wire clearance analyst"),
        ("usr-023", "node-user-george", "George Bailey", "george.bailey", "Operations", "Network Engineer", "ADMIN", "EMPLOYEE", 0.80, "HEALTHY", "Senior Network Core Infrastructure Engineer"),
        ("usr-024", "node-user-nina", "Nina Simone", "nina.simone", "Data", "Data Scientist", "USER", "EMPLOYEE", 0.55, "HEALTHY", "BI & Data Analytics Engineer"),
        ("usr-025", "node-user-breakglass", "admin-breakglass-01", "admin_breakglass_01", "Security", "Breakglass Admin", "DOMAIN_ADMIN", "EMERGENCY_BREAKGLASS", 1.0, "HEALTHY", "Emergency break-glass domain admin account"),
        ("usr-026", "node-user-carlos", "Carlos Santana", "carlos.santana", "Engineering", "Cloud Engineer", "ELEVATED", "EMPLOYEE", 0.75, "HEALTHY", "Kubernetes cluster operations engineer"),
        ("usr-027", "node-user-emily", "Emily Watson", "emily.watson", "HR", "Payroll Specialist", "USER", "EMPLOYEE", 0.70, "HEALTHY", "Monthly payroll processing specialist"),
        ("usr-028", "node-user-brian", "Brian Cox", "brian.cox", "Engineering", "Security Researcher", "ELEVATED", "EMPLOYEE", 0.70, "HEALTHY", "Zero-day vulnerability triage researcher"),
        ("usr-029", "node-user-hannah", "Hannah Abbott", "hannah.abbott", "IT Support", "Helpdesk Tier 1", "USER", "EMPLOYEE", 0.40, "HEALTHY", "Desktop support & onboarding technician"),
        ("usr-030", "node-user-svc-monitoring", "svc-datadog-agent", "svc_datadog_agent", "Operations", "Service Account", "USER", "SERVICE_ACCOUNT", 0.60, "HEALTHY", "Cloud infrastructure APM monitoring agent"),
    ]

    for uid, nid, name, uname, dept, role, priv, atype, crit, sec_stat, desc in user_data:
        nodes.append({
            "node_id": nid,
            "node_type": "USER" if "svc" not in nid else "SERVICE_ACCOUNT",
            "name": name,
            "hostname": f"{uname}.identity.corp.internal",
            "ip_address": f"10.100.1.{len(nodes)+1}",
            "environment": "CORP",
            "department": dept,
            "owner": name,
            "criticality": crit,
            "business_value": round(crit * 100000.0, 2),
            "exposure": "INTERNAL",
            "security_status": sec_stat,
            "description": desc,
            "tags": f"identity;{dept.lower()};{priv.lower()}"
        })

    # 1.2 ENDPOINTS & WORKSTATIONS (25 Endpoints)
    for i in range(1, 26):
        user_ref = user_data[i-1]
        is_marcus = (user_ref[1] == "node-user-marcus")
        ep_id = f"node-ep-ws{i:02d}" if not is_marcus else "node-ep-laptop-marcus"
        sec_stat = "COMPROMISED" if is_marcus else ("SUSPECTED" if i in [2, 10] else "HEALTHY")
        nodes.append({
            "node_id": ep_id,
            "node_type": "LAPTOP" if i <= 15 else "WORKSTATION",
            "name": f"{user_ref[2]} Laptop" if i <= 15 else f"{user_ref[2]} Workstation",
            "hostname": f"ws-{user_ref[3].replace('_', '-')}.corp.internal",
            "ip_address": f"10.100.10.{i}",
            "environment": "CORP",
            "department": user_ref[4],
            "owner": user_ref[2],
            "criticality": round(user_ref[8] * 0.7, 2),
            "business_value": 3500.0,
            "exposure": "INTERNAL",
            "security_status": sec_stat,
            "description": f"Managed enterprise workstation assigned to {user_ref[2]}",
            "tags": f"endpoint;workstation;tier3;{user_ref[4].lower()}"
        })

    # 1.3 SERVERS & JUMP HOSTS (25 Servers)
    server_data = [
        ("node-srv-jumpbox01", "Jumpbox Bastion 01", "bastion-01.mgmt.internal", "10.200.1.10", "PROD", "DevOps", 0.90, "DMZ", "VULNERABLE", "Primary SSH Bastion Jump Host protecting production clusters"),
        ("node-srv-jumpbox02", "Jumpbox Bastion 02 (Secondary)", "bastion-02.mgmt.internal", "10.200.1.11", "PROD", "DevOps", 0.85, "DMZ", "HEALTHY", "Secondary failover SSH Bastion Jump Host"),
        ("node-srv-dc01", "Primary Active Directory DC", "dc-01.corp.internal", "10.100.0.10", "CORP", "IT Operations", 0.95, "INTERNAL", "MONITORED", "Primary Active Directory Domain Controller and Kerberos KDC"),
        ("node-srv-dc02", "Replica Active Directory DC", "dc-02.corp.internal", "10.100.0.11", "CORP", "IT Operations", 0.90, "INTERNAL", "HEALTHY", "Backup Active Directory Domain Controller"),
        ("node-srv-idp-okta", "Okta Identity Sync Bridge", "idp-bridge.auth.internal", "10.100.0.25", "CORP", "Security", 0.95, "INTERNAL", "HEALTHY", "Enterprise Identity Provider authentication sync server"),
        ("node-srv-web-public", "Public Citizen Web Portal Front", "web-portal.dmz.internal", "192.168.1.10", "PROD", "Engineering", 0.80, "INTERNET_FACING", "VULNERABLE", "Nginx reverse proxy facing public internet"),
        ("node-srv-api-gateway", "Enterprise API Gateway Core", "api-gw.prod.internal", "10.200.2.10", "PROD", "Engineering", 0.90, "DMZ", "MONITORED", "Kong API Gateway routing incoming API requests to backend microservices"),
        ("node-srv-payment-app01", "Payment Processing Host 01", "pay-app01.prod.internal", "10.200.3.10", "PROD", "Payments", 0.95, "RESTRICTED_ISOLATED", "MONITORED", "Production payment execution application host"),
        ("node-srv-payment-app02", "Payment Processing Host 02", "pay-app02.prod.internal", "10.200.3.11", "PROD", "Payments", 0.95, "RESTRICTED_ISOLATED", "HEALTHY", "Redundant payment execution application host"),
        ("node-srv-vault01", "HashiCorp Secret Vault Cluster", "vault-01.sec.internal", "10.200.0.50", "PROD", "Security", 0.98, "RESTRICTED_ISOLATED", "HEALTHY", "Secrets management, PKI certificates, and dynamic credential broker"),
        ("node-srv-siem-splunk", "Splunk Enterprise SIEM Indexer", "splunk-core.sec.internal", "10.100.5.10", "CORP", "Security", 0.85, "INTERNAL", "HEALTHY", "Centralized security telemetry indexer & alert correlation engine"),
        ("node-srv-edr-console", "CrowdStrike Falcon Sensor Relay", "edr-relay.sec.internal", "10.100.5.20", "CORP", "Security", 0.80, "INTERNAL", "HEALTHY", "Enterprise endpoint detection & response sensor proxy"),
        ("node-srv-gitlab", "GitLab Enterprise SCM Server", "gitlab.dev.internal", "10.100.20.10", "DEV", "Engineering", 0.85, "INTERNAL", "MONITORED", "Source code repository and CI/CD orchestration controller"),
        ("node-srv-k8s-master01", "Kubernetes Master Node 01", "k8s-m01.prod.internal", "10.200.10.10", "PROD", "DevOps", 0.92, "INTERNAL", "HEALTHY", "Kubernetes container control plane node"),
        ("node-srv-k8s-worker01", "Kubernetes Worker Node 01", "k8s-w01.prod.internal", "10.200.10.21", "PROD", "DevOps", 0.85, "INTERNAL", "HEALTHY", "Kubernetes application worker executing microservices"),
        ("node-srv-k8s-worker02", "Kubernetes Worker Node 02", "k8s-w02.prod.internal", "10.200.10.22", "PROD", "DevOps", 0.85, "INTERNAL", "HEALTHY", "Kubernetes application worker executing backend workers"),
        ("node-srv-backup-primary", "Veeam Backup Repository Host", "backup-srv.ops.internal", "10.100.30.10", "PROD", "IT Operations", 0.95, "RESTRICTED_ISOLATED", "HEALTHY", "Air-gapped immutable backup repository server"),
        ("node-srv-mail-relay", "Corporate Exchange Mail Relay", "mail-relay.corp.internal", "10.100.2.10", "CORP", "IT Operations", 0.70, "DMZ", "HEALTHY", "Inbound/Outbound SMTP TLS mail gateway"),
        ("node-srv-dns-internal", "Internal DNS Core Resolvers", "dns-core.net.internal", "10.100.0.5", "CORP", "IT Operations", 0.88, "INTERNAL", "HEALTHY", "Enterprise recursive DNS nameserver"),
        ("node-srv-hr-portal", "Workday HR Integration Host", "hr-portal.corp.internal", "10.100.15.10", "CORP", "HR", 0.75, "INTERNAL", "HEALTHY", "Human resources employee management application host"),
        ("node-srv-finance-erp", "SAP S/4HANA Finance Host", "sap-erp.fin.internal", "10.200.40.10", "PROD", "Finance", 0.94, "RESTRICTED_ISOLATED", "HEALTHY", "Enterprise financial ledger and payroll ERP server"),
        ("node-srv-vpn-concentrator", "GlobalProtect VPN Gateway", "vpn-gw.net.internal", "192.168.1.5", "CORP", "IT Operations", 0.85, "INTERNET_FACING", "VULNERABLE", "Remote access SSL-VPN concentrator for workforce"),
        ("node-srv-pki-ca", "Corporate Offline Root CA", "ca-root.sec.internal", "10.200.0.5", "PROD", "Security", 0.99, "RESTRICTED_ISOLATED", "HEALTHY", "Internal Public Key Infrastructure issuing authority"),
        ("node-srv-monitoring-elk", "Elasticsearch Telemetry Cluster", "elk-core.ops.internal", "10.100.5.30", "CORP", "Operations", 0.75, "INTERNAL", "HEALTHY", "Application observability metrics & tracing store"),
        ("node-srv-staging-api", "Staging Environment API Host", "api-stage.dev.internal", "10.100.50.10", "STAGE", "Engineering", 0.50, "DMZ", "SUSPECTED", "Pre-production testing API endpoint server"),
    ]

    for nid, name, host, ip, env, dept, crit, exp, sec_stat, desc in server_data:
        nodes.append({
            "node_id": nid,
            "node_type": "SERVER" if "jumpbox" not in nid else "SERVER",
            "name": name,
            "hostname": host,
            "ip_address": ip,
            "environment": env,
            "department": dept,
            "owner": "Infrastructure Team",
            "criticality": crit,
            "business_value": round(crit * 500000.0, 2),
            "exposure": exp,
            "security_status": sec_stat,
            "description": desc,
            "tags": f"server;infra;{env.lower()};{exp.lower()}"
        })

    # 1.4 DATABASES (15 Databases)
    database_data = [
        ("node-db-customer-core", "Crown Jewel: Customer Core PII Database", "db-cust-core.prod.internal", "10.200.4.50", "PROD", "Payments", 1.0, "RESTRICTED_ISOLATED", "HEALTHY", True, "PostgreSQL HA Cluster storing 5M+ decrypted citizen records & KYC PII"),
        ("node-db-payment-ledger", "Crown Jewel: Real-Time Payment Transaction Ledger", "db-pay-ledger.prod.internal", "10.200.4.51", "PROD", "Payments", 1.0, "RESTRICTED_ISOLATED", "HEALTHY", True, "Financial transaction ledger processing $2.4M/hr real-time transactions"),
        ("node-db-id-vault", "Crown Jewel: Sovereign Identity Auth Credential Store", "db-id-vault.auth.internal", "10.200.0.60", "PROD", "Security", 1.0, "RESTRICTED_ISOLATED", "HEALTHY", True, "Hardware security module backed biometric and password hash vault"),
        ("node-db-finance-ledger", "Corporate General Finance Ledger", "db-fin-ledger.fin.internal", "10.200.40.20", "PROD", "Finance", 0.95, "RESTRICTED_ISOLATED", "HEALTHY", True, "SAP HANA general financial accounts & tax ledger"),
        ("node-db-hr-records", "Confidential Employee HR Database", "db-hr-emp.corp.internal", "10.100.15.20", "CORP", "HR", 0.85, "INTERNAL", "HEALTHY", False, "Employee contracts, medical insurance, and salary records"),
        ("node-db-audit-ledger", "Chained Cryptographic Audit Ledger", "db-audit-chain.sec.internal", "10.200.0.70", "PROD", "Security", 0.95, "RESTRICTED_ISOLATED", "HEALTHY", True, "Immutable SHA-256 anchored incident & decision event ledger"),
        ("node-db-inventory-core", "Supply Chain Inventory Catalog", "db-inv.prod.internal", "10.200.12.10", "PROD", "Operations", 0.70, "INTERNAL", "HEALTHY", False, "Warehouse asset and product catalog MongoDB cluster"),
        ("node-db-telemetry-cache", "Redis Real-Time Session Cache", "redis-cache.prod.internal", "10.200.2.30", "PROD", "Engineering", 0.80, "INTERNAL", "HEALTHY", False, "In-memory Redis session state cache for active web users"),
        ("node-db-analytics-lake", "Snowflake Analytics Data Warehouse", "dw-analytics.cloud.internal", "10.200.60.10", "PROD", "Data", 0.75, "INTERNAL", "HEALTHY", False, "De-identified business intelligence analytical data warehouse"),
        ("node-db-billing-gateway", "Credit Card Tokenization Vault", "db-token-vault.prod.internal", "10.200.4.55", "PROD", "Payments", 0.98, "RESTRICTED_ISOLATED", "HEALTHY", True, "PCI-DSS Level 1 tokenized PAN payment card vault"),
        ("node-db-backup-catalog", "Veeam Deduplication Metadata DB", "db-backup-cat.ops.internal", "10.100.30.20", "PROD", "IT Operations", 0.90, "RESTRICTED_ISOLATED", "HEALTHY", False, "Catalog tracking all virtual machine backup restore points"),
        ("node-db-gitlab-postgres", "GitLab CI Metadata Store", "db-gitlab.dev.internal", "10.100.20.20", "DEV", "Engineering", 0.70, "INTERNAL", "HEALTHY", False, "Source code commits, pull requests, and CI pipeline state"),
        ("node-db-siem-hotstorage", "Splunk Elastic Cold Storage DB", "db-siem-store.sec.internal", "10.100.5.15", "CORP", "Security", 0.80, "INTERNAL", "HEALTHY", False, "Forensic log archives with 365-day compliance retention"),
        ("node-db-staging-test", "Staging Database Mirror", "db-stage.dev.internal", "10.100.50.20", "STAGE", "Engineering", 0.40, "DMZ", "SUSPECTED", False, "Synthetic test data database for developer pre-release builds"),
        ("node-db-keycloak-sso", "Keycloak Federation SSO DB", "db-sso.auth.internal", "10.200.0.65", "PROD", "Security", 0.92, "INTERNAL", "HEALTHY", True, "OAuth2 and SAML token signing database"),
    ]

    for nid, name, host, ip, env, dept, crit, exp, sec_stat, is_crown, desc in database_data:
        nodes.append({
            "node_id": nid,
            "node_type": "DATABASE",
            "name": name,
            "hostname": host,
            "ip_address": ip,
            "environment": env,
            "department": dept,
            "owner": "Data Architecture Lead",
            "criticality": crit,
            "business_value": round(crit * 1000000.0, 2),
            "exposure": exp,
            "security_status": sec_stat,
            "description": desc,
            "tags": f"database;storage;{'crown_jewel;' if is_crown else ''}{dept.lower()}"
        })

    # 1.5 APPLICATIONS (15 Applications)
    app_data = [
        ("node-app-payment-gateway", "Citizen Payment Gateway Microservice", "pay-gw.prod.internal", "10.200.3.15", "PROD", "Payments", 0.98, "INTERNAL", "HEALTHY", "Core payments engine dispatching card clearance and settlement requests"),
        ("node-app-citizen-portal", "Citizen Digital Services Web Front", "portal.gov.internal", "10.200.2.15", "PROD", "Engineering", 0.90, "INTERNET_FACING", "MONITORED", "Citizen identity verification and public document submission portal"),
        ("node-app-auth-service", "Single Sign-On Authentication Engine", "sso-engine.auth.internal", "10.200.0.20", "PROD", "Security", 0.96, "INTERNAL", "HEALTHY", "OAuth2/OIDC token issuance service verifying workforce & citizen logons"),
        ("node-app-payroll-proc", "Monthly Automated Payroll Processor", "payroll-proc.fin.internal", "10.200.40.15", "PROD", "Finance", 0.90, "RESTRICTED_ISOLATED", "HEALTHY", "Automated batch daemon processing direct-deposit salary allocations"),
        ("node-app-cloud-sync", "Cross-Cloud Data Synchronization Engine", "cloud-sync.prod.internal", "10.200.10.35", "PROD", "DevOps", 0.85, "INTERNAL", "MONITORED", "Async microservice replicating transaction logs to backup S3 buckets"),
        ("node-app-hr-manager", "Employee Profile & Benefits Manager", "hr-mgr.corp.internal", "10.100.15.15", "CORP", "HR", 0.70, "INTERNAL", "HEALTHY", "Enterprise HR frontend for employee lifecycle management"),
        ("node-app-admin-console", "Internal Cloud Administration Console", "admin-console.mgmt.internal", "10.200.1.50", "PROD", "DevOps", 0.95, "RESTRICTED_ISOLATED", "HEALTHY", "Privileged web management GUI for infrastructure orchestration"),
        ("node-app-siem-ingest", "High-Volume Telemetry Collector", "siem-ingest.sec.internal", "10.100.5.12", "CORP", "Security", 0.80, "INTERNAL", "HEALTHY", "Kafka-backed log ingestion consumer pipeline"),
        ("node-app-email-exchange", "Microsoft Exchange Hybrid Mail Worker", "exchange.corp.internal", "10.100.2.15", "CORP", "IT Operations", 0.75, "INTERNAL", "HEALTHY", "Enterprise email mailbox and calendar synchronization service"),
        ("node-app-support-desk", "Jira IT Service Management Service", "jira-itsm.corp.internal", "10.100.25.10", "CORP", "IT Support", 0.65, "INTERNAL", "HEALTHY", "Incident ticketing and employee service request management application"),
        ("node-app-fraud-engine", "Real-Time AI Fraud Detection Daemon", "fraud-ai.prod.internal", "10.200.3.25", "PROD", "Payments", 0.92, "INTERNAL", "HEALTHY", "Machine learning inference pipeline scoring transaction anomalies"),
        ("node-app-file-transfer", "Secure SFTP External Banking Bridge", "sftp-bank.fin.internal", "10.200.40.30", "PROD", "Finance", 0.88, "DMZ", "VULNERABLE", "SFTP service transmitting automated clearing house (ACH) batches to central banks"),
        ("node-app-developer-ide", "GitLab Web IDE Workspace Engine", "dev-ide.dev.internal", "10.100.20.15", "DEV", "Engineering", 0.60, "INTERNAL", "HEALTHY", "Containerized browser IDE instances for development staff"),
        ("node-app-vpn-clientmgr", "VPN Client Profile Distribution App", "vpn-profiles.net.internal", "10.100.0.30", "CORP", "IT Operations", 0.70, "INTERNAL", "HEALTHY", "Internal PKI certificate and VPN configuration distributor"),
        ("node-app-staging-mock", "Synthetic Mock Third-Party Bank API", "mock-bank.dev.internal", "10.100.50.30", "STAGE", "Engineering", 0.40, "DMZ", "HEALTHY", "Sandbox banking API mock for staging load tests"),
    ]

    for nid, name, host, ip, env, dept, crit, exp, sec_stat, desc in app_data:
        nodes.append({
            "node_id": nid,
            "node_type": "APPLICATION",
            "name": name,
            "hostname": host,
            "ip_address": ip,
            "environment": env,
            "department": dept,
            "owner": "Application Engineering",
            "criticality": crit,
            "business_value": round(crit * 400000.0, 2),
            "exposure": exp,
            "security_status": sec_stat,
            "description": desc,
            "tags": f"application;microservice;{env.lower()};{dept.lower()}"
        })

    # 1.6 CLOUD RESOURCES, FIREWALLS & STORAGE (10 Nodes)
    cloud_data = [
        ("node-cld-s3-lake", "AWS S3 Sovereign Data Lake Bucket", "s3-sovereign-lake.aws", "10.250.1.1", "PROD", "Data", 0.90, "INTERNAL", "MONITORED", "Encrypted S3 bucket storing enterprise data backups and raw telemetry"),
        ("node-cld-iam-role", "AWS IAM SuperAdmin Role", "arn:aws:iam::role/SuperAdmin", "10.250.0.1", "PROD", "DevOps", 0.98, "INTERNAL", "MONITORED", "Privileged cloud IAM execution role with full cross-account control"),
        ("node-cld-keyvault", "Azure Key Vault Sovereign Key Store", "sovereign-vault.vault.azure.net", "10.250.2.1", "PROD", "Security", 0.95, "INTERNAL", "HEALTHY", "Cloud hardware security module for envelope encryption keys"),
        ("node-net-fw-perimeter", "Edge Next-Gen Firewall (Palo Alto)", "ngfw-edge.net.internal", "192.168.1.1", "PROD", "Security", 0.95, "INTERNET_FACING", "HEALTHY", "Perimeter stateful packet inspection firewall and IPS"),
        ("node-net-fw-internal", "East-West Microsegmentation Firewall", "ngfw-internal.net.internal", "10.200.0.1", "PROD", "Security", 0.92, "INTERNAL", "HEALTHY", "Zero-trust internal firewall isolating Payment zone from Corp LAN"),
        ("node-net-waf", "Cloudflare Enterprise Web App Firewall", "waf.cloudflare.internal", "192.168.1.2", "PROD", "Security", 0.90, "INTERNET_FACING", "HEALTHY", "Layer 7 DDoS protection and OWASP Top 10 mitigation proxy"),
        ("node-sto-san-core", "NetApp Enterprise SAN Storage Array", "san-core.ops.internal", "10.200.5.10", "PROD", "IT Operations", 0.92, "RESTRICTED_ISOLATED", "HEALTHY", "Fibre Channel SAN array hosting production virtual machine LUNs"),
        ("node-sec-edr-mgmt", "CrowdStrike Falcon Cloud Console", "falcon.crowdstrike.cloud", "10.250.5.1", "PROD", "Security", 0.85, "INTERNAL", "HEALTHY", "Central management plane for endpoint agent policies"),
        ("node-cld-k8s-cluster", "AWS EKS Production Kubernetes Cluster", "eks-prod.aws.internal", "10.200.10.1", "PROD", "DevOps", 0.94, "INTERNAL", "HEALTHY", "Elastic Kubernetes service hosting 40+ containerized pods"),
        ("node-bak-immutable", "AWS S3 Glacier Vault (Immutable WORM)", "s3-glacier-worm.aws", "10.250.3.1", "PROD", "IT Operations", 0.95, "RESTRICTED_ISOLATED", "HEALTHY", "Write-Once-Read-Many regulatory compliance disaster recovery archive"),
    ]

    for nid, name, host, ip, env, dept, crit, exp, sec_stat, desc in cloud_data:
        ntype = "FIREWALL" if "fw" in nid or "waf" in nid else ("CLOUD_RESOURCE" if "cld" in nid else "STORAGE")
        nodes.append({
            "node_id": nid,
            "node_type": ntype,
            "name": name,
            "hostname": host,
            "ip_address": ip,
            "environment": env,
            "department": dept,
            "owner": "Security Engineering",
            "criticality": crit,
            "business_value": round(crit * 600000.0, 2),
            "exposure": exp,
            "security_status": sec_stat,
            "description": desc,
            "tags": f"{ntype.lower()};cloud;infrastructure"
        })

    print(f"  [OK] Generated {len(nodes)} nodes.")

    # Write nodes.csv
    nodes_csv_path = os.path.join(OUTPUT_DIR, "nodes.csv")
    with open(nodes_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "node_id", "node_type", "name", "hostname", "ip_address", "environment",
            "department", "owner", "criticality", "business_value", "exposure",
            "security_status", "description", "tags"
        ])
        writer.writeheader()
        writer.writerows(nodes)

    node_ids = set(n["node_id"] for n in nodes)

    # =========================================================================
    # 2. RELATIONSHIPS (280 Relationships)
    # =========================================================================
    relationships = []
    rel_counter = 1

    def add_rel(src, tgt, rtype, priv="USER", risk=20.0, conf=0.95, disc="Active_Directory", desc=""):
        nonlocal rel_counter
        assert src in node_ids, f"Unknown source node: {src}"
        assert tgt in node_ids, f"Unknown target node: {tgt}"
        rid = f"rel-{rel_counter:04d}"
        rel_counter += 1
        relationships.append({
            "relationship_id": rid,
            "source_id": src,
            "target_id": tgt,
            "relationship_type": rtype,
            "privilege_level": priv,
            "risk_score": risk,
            "confidence": conf,
            "discovered_by": disc,
            "timestamp": (BASE_TIME + timedelta(minutes=rel_counter*5)).isoformat(),
            "description": desc or f"{src} {rtype} {tgt}"
        })
        return rid

    # 2.1 User -> Workstation relationships (USES_DEVICE)
    for i in range(1, 26):
        user_nid = user_data[i-1][1]
        ep_id = f"node-ep-ws{i:02d}" if user_nid != "node-user-marcus" else "node-ep-laptop-marcus"
        add_rel(user_nid, ep_id, "USES_DEVICE", "USER", 15.0, 0.99, "CrowdStrike_EDR", f"User {user_nid} primary assigned hardware")

    # 2.2 Workstations -> Active Directory / Network / DNS
    for i in range(1, 26):
        ep_id = f"node-ep-ws{i:02d}" if i != 1 else "node-ep-laptop-marcus"
        add_rel(ep_id, "node-srv-dc01", "AUTHENTICATES_TO", "USER", 25.0, 0.98, "Active_Directory", "Kerberos ticket granting service")
        add_rel(ep_id, "node-srv-dns-internal", "CONNECTS_TO", "USER", 10.0, 0.99, "NetFlow", "Recursive internal DNS resolution")

    # 2.3 Marcus Vance Lateral Movement Sequence (Judge Demo Scenario 1 - Path 1)
    # Marcus -> Laptop -> Jumpbox01 -> Payment Gateway -> Customer Core DB
    r_m1 = add_rel("node-user-marcus", "node-ep-laptop-marcus", "HAS_ACCESS", "USER", 75.0, 0.99, "Splunk_SIEM", "Marcus interactive desktop session")
    r_m2 = add_rel("node-ep-laptop-marcus", "node-srv-jumpbox01", "CONNECTS_TO", "ADMIN", 85.0, 0.92, "CrowdStrike_EDR", "Compromised SSH private key cached in memory utilized to pivot to Jumpbox")
    r_m3 = add_rel("node-srv-jumpbox01", "node-app-payment-gateway", "ADMIN_ACCESS", "ADMIN", 90.0, 0.88, "NetFlow", "Bastion administrative SSH tunnel to payment microservice")
    r_m4 = add_rel("node-app-payment-gateway", "node-db-customer-core", "HAS_ACCESS", "ADMIN", 95.0, 0.95, "App_Config", "Direct database connection pool holding decrypted citizen table credentials")
    
    # Alternative route for Marcus (Path 2):
    # Marcus -> Laptop -> VPN -> Staging API -> Jumpbox02 -> Customer DB
    r_m5 = add_rel("node-ep-laptop-marcus", "node-srv-vpn-concentrator", "AUTHENTICATES_TO", "USER", 70.0, 0.90, "VPN_Logs", "Remote access session via GlobalProtect")
    r_m6 = add_rel("node-srv-vpn-concentrator", "node-srv-staging-api", "CAN_REACH", "USER", 65.0, 0.85, "Firewall_Logs", "Network route from VPN pool to staging network")
    r_m7 = add_rel("node-srv-staging-api", "node-srv-jumpbox02", "CONNECTS_TO", "USER", 75.0, 0.70, "CrowdStrike_EDR", "Suspected unsegmented debug connection to secondary jumpbox")
    r_m8 = add_rel("node-srv-jumpbox02", "node-db-customer-core", "CONNECTS_TO", "ADMIN", 85.0, 0.80, "DB_Audit", "Secondary administrative maintenance route")

    # 2.4 External Web Exploitation Sequence (Judge Demo Scenario 2)
    # Perimeter FW -> Web Portal -> API Gateway -> Sovereign ID Vault
    r_e1 = add_rel("node-net-fw-perimeter", "node-srv-web-public", "CAN_REACH", "USER", 80.0, 0.99, "Edge_FW", "Inbound HTTPS 443 port forward to Web Portal")
    r_e2 = add_rel("node-srv-web-public", "node-app-citizen-portal", "HOSTS", "USER", 85.0, 0.99, "Nginx_Config", "Web portal application running on public server")
    r_e3 = add_rel("node-app-citizen-portal", "node-srv-api-gateway", "CONNECTS_TO", "USER", 85.0, 0.95, "API_Logs", "Backend API requests forwarded through API gateway")
    r_e4 = add_rel("node-srv-api-gateway", "node-app-auth-service", "DEPENDS_ON", "SERVICE", 90.0, 0.96, "Kong_Route", "Authentication token verification hook")
    r_e5 = add_rel("node-app-auth-service", "node-db-id-vault", "HAS_ACCESS", "ROOT", 95.0, 0.98, "Vault_Client", "Hardware security module backed biometric and token verification")

    # 2.5 Cloud CI/CD Compromise Sequence (Judge Demo Scenario 3)
    # svc-cicd-pipeline -> GitLab Server -> K8s Master -> AWS IAM Role -> S3 Lake -> Finance DB
    r_c1 = add_rel("node-user-svc-cicd", "node-srv-gitlab", "AUTHENTICATES_TO", "ADMIN", 80.0, 0.95, "GitLab_Audit", "CI runner access token with deploy privileges")
    r_c2 = add_rel("node-srv-gitlab", "node-srv-k8s-master01", "CONNECTS_TO", "ADMIN", 88.0, 0.92, "Kube_API", "Kubernetes cluster administrative deployment webhook")
    r_c3 = add_rel("node-srv-k8s-master01", "node-cld-iam-role", "ADMIN_ACCESS", "ROOT", 92.0, 0.90, "AWS_CloudTrail", "Node instance profile assuming SuperAdmin IAM role")
    r_c4 = add_rel("node-cld-iam-role", "node-cld-s3-lake", "OWNS", "ROOT", 90.0, 0.99, "AWS_IAM", "Full read/write permissions on sovereign data lake")
    r_c5 = add_rel("node-cld-s3-lake", "node-db-payment-ledger", "BACKED_UP_BY", "SERVICE", 85.0, 0.90, "S3_Lifecycle", "Daily raw transaction ledger archive bucket")

    # 2.6 Application -> Infrastructure Dependencies
    add_rel("node-app-payment-gateway", "node-srv-payment-app01", "RUNS_ON", "USER", 10.0, 0.99, "Systemd", "Payment gateway running on app host 1")
    add_rel("node-app-payment-gateway", "node-srv-payment-app02", "RUNS_ON", "USER", 10.0, 0.99, "Systemd", "Payment gateway running on app host 2")
    add_rel("node-app-payment-gateway", "node-db-payment-ledger", "HAS_ACCESS", "ADMIN", 95.0, 0.99, "JDBC_Pool", "Direct synchronous write to payment ledger")
    add_rel("node-app-payment-gateway", "node-db-billing-gateway", "CONNECTS_TO", "ADMIN", 90.0, 0.98, "PCI_Enclave", "Credit card tokenization lookup")
    add_rel("node-app-payment-gateway", "node-app-fraud-engine", "DEPENDS_ON", "SERVICE", 80.0, 0.95, "gRPC", "Real-time AI fraud transaction validation")

    add_rel("node-app-payroll-proc", "node-srv-finance-erp", "RUNS_ON", "USER", 15.0, 0.99, "SAP_Kernel", "Payroll processor running on SAP ERP host")
    add_rel("node-app-payroll-proc", "node-db-finance-ledger", "HAS_ACCESS", "ADMIN", 92.0, 0.99, "HANA_Driver", "Direct ledger entry commit")
    add_rel("node-app-payroll-proc", "node-app-file-transfer", "DEPENDS_ON", "SERVICE", 85.0, 0.90, "SFTP_Client", "ACH batch distribution to central bank clearing")

    add_rel("node-app-citizen-portal", "node-srv-web-public", "RUNS_ON", "USER", 15.0, 0.99, "Docker", "Citizen portal container on web host")
    add_rel("node-app-citizen-portal", "node-db-telemetry-cache", "DEPENDS_ON", "USER", 50.0, 0.95, "Redis_Client", "Active session token store")

    # 2.7 Database Backup Relationships
    add_rel("node-db-customer-core", "node-srv-backup-primary", "BACKED_UP_BY", "SERVICE", 15.0, 0.98, "Veeam_Agent", "Nightly encrypted snapshot")
    add_rel("node-db-payment-ledger", "node-srv-backup-primary", "BACKED_UP_BY", "SERVICE", 15.0, 0.98, "Veeam_Agent", "Hourly incremental differential backup")
    add_rel("node-db-id-vault", "node-srv-backup-primary", "BACKED_UP_BY", "SERVICE", 20.0, 0.95, "Veeam_Agent", "Air-gapped key escrow archive")
    add_rel("node-srv-backup-primary", "node-bak-immutable", "CONNECTS_TO", "ADMIN", 10.0, 0.99, "S3_WORM", "Immutable off-site replication")

    # 2.8 Security Monitoring Infrastructure (SIEM & EDR)
    for srv in [s[0] for s in server_data]:
        add_rel(srv, "node-srv-siem-splunk", "COMMUNICATES_WITH", "USER", 5.0, 0.99, "Syslog_TLS", f"{srv} forward syslog to Splunk")
        add_rel(srv, "node-srv-edr-console", "COMMUNICATES_WITH", "USER", 5.0, 0.99, "CrowdStrike_Relay", f"{srv} endpoint telemetry to Falcon")

    # 2.9 Network & Firewall Controls
    add_rel("node-net-fw-perimeter", "node-net-waf", "CONNECTS_TO", "USER", 5.0, 0.99, "Net_Config", "Perimeter traffic routed through WAF")
    add_rel("node-net-waf", "node-srv-web-public", "CAN_REACH", "USER", 15.0, 0.99, "Reverse_Proxy", "Clean HTTP requests forwarded to web frontend")
    add_rel("node-net-fw-internal", "node-srv-payment-app01", "CONTROLLED_BY", "ADMIN", 10.0, 0.99, "ACL_Rule", "Microsegmentation rule isolating Payment Node 1")
    add_rel("node-net-fw-internal", "node-srv-payment-app02", "CONTROLLED_BY", "ADMIN", 10.0, 0.99, "ACL_Rule", "Microsegmentation rule isolating Payment Node 2")
    add_rel("node-net-fw-internal", "node-db-customer-core", "CONTROLLED_BY", "ADMIN", 10.0, 0.99, "ACL_Rule", "Strict database subnet isolation")

    # 2.10 Admin & Privileged Access
    add_rel("node-user-sarah", "node-srv-jumpbox01", "ADMIN_ACCESS", "ADMIN", 40.0, 0.99, "Okta_MFA", "DevOps Admin MFA session to Bastion")
    add_rel("node-user-sarah", "node-cld-iam-role", "ADMIN_ACCESS", "ROOT", 50.0, 0.95, "AWS_SSO", "Cloud infrastructure admin role assumption")
    add_rel("node-user-priya", "node-srv-jumpbox01", "ADMIN_ACCESS", "ADMIN", 45.0, 0.99, "Okta_MFA", "DBA MFA access to maintenance jumpbox")
    add_rel("node-user-priya", "node-db-customer-core", "ADMIN_ACCESS", "ADMIN", 50.0, 0.99, "DB_Audit", "Authorized DBA maintenance query access")
    add_rel("node-user-priya", "node-db-payment-ledger", "ADMIN_ACCESS", "ADMIN", 50.0, 0.99, "DB_Audit", "Authorized DBA maintenance query access")
    add_rel("node-user-breakglass", "node-srv-dc01", "ADMIN_ACCESS", "DOMAIN_ADMIN", 80.0, 0.90, "CyberArk_Vault", "Emergency Breakglass Domain Admin check-out")

    # 2.11 Inter-Service & Kubernetes Cluster Communication
    add_rel("node-srv-k8s-master01", "node-srv-k8s-worker01", "MANAGES", "ROOT", 10.0, 0.99, "Kubelet", "K8s worker 1 orchestration")
    add_rel("node-srv-k8s-master01", "node-srv-k8s-worker02", "MANAGES", "ROOT", 10.0, 0.99, "Kubelet", "K8s worker 2 orchestration")
    add_rel("node-srv-k8s-worker01", "node-cld-k8s-cluster", "MEMBER_OF", "USER", 5.0, 0.99, "Cluster_Config", "Worker node joined to EKS cluster")
    add_rel("node-srv-k8s-worker02", "node-cld-k8s-cluster", "MEMBER_OF", "USER", 5.0, 0.99, "Cluster_Config", "Worker node joined to EKS cluster")

    # 2.12 Additional business and cross-system relationships to reach >= 280
    departments = ["Engineering", "Finance", "HR", "Operations"]
    for idx, u in enumerate(user_data[10:]):
        user_nid = u[1]
        # User to departmental applications
        if u[4] == "Finance":
            add_rel(user_nid, "node-app-payroll-proc", "HAS_ACCESS", "USER", 25.0, 0.95, "Okta_SSO", f"{u[2]} access to payroll app")
            add_rel(user_nid, "node-srv-finance-erp", "AUTHENTICATES_TO", "USER", 20.0, 0.95, "SAP_Logon", f"{u[2]} logon to SAP ERP")
        elif u[4] == "HR":
            add_rel(user_nid, "node-app-hr-manager", "HAS_ACCESS", "USER", 20.0, 0.95, "Okta_SSO", f"{u[2]} access to HR manager")
            add_rel(user_nid, "node-db-hr-records", "HAS_ACCESS", "USER", 25.0, 0.90, "DB_Audit", f"{u[2]} query employee records")
        elif u[4] == "Engineering":
            add_rel(user_nid, "node-srv-gitlab", "AUTHENTICATES_TO", "USER", 20.0, 0.98, "GitLab_SSH", f"{u[2]} git commit access")
            add_rel(user_nid, "node-app-developer-ide", "HAS_ACCESS", "USER", 15.0, 0.95, "Web_Session", f"{u[2]} cloud workspace access")
        else:
            add_rel(user_nid, "node-app-support-desk", "HAS_ACCESS", "USER", 10.0, 0.99, "Okta_SSO", f"{u[2]} ITSM portal access")
            add_rel(user_nid, "node-app-email-exchange", "HAS_ACCESS", "USER", 10.0, 0.99, "Exchange_ActiveSync", f"{u[2]} corporate email access")

    # Fill remainder systematically to guarantee exactly >= 280
    while len(relationships) < 285:
        src = random.choice([n["node_id"] for n in nodes if "node-ep-" in n["node_id"]])
        tgt = random.choice(["node-srv-mail-relay", "node-app-support-desk", "node-srv-monitoring-elk", "node-srv-staging-api", "node-app-citizen-portal"])
        if src != tgt:
            add_rel(src, tgt, "COMMUNICATES_WITH", "USER", round(random.uniform(10.0, 45.0), 1), round(random.uniform(0.70, 0.99), 2), "NetFlow", f"Periodic telemetry communication from {src} to {tgt}")

    print(f"  [OK] Generated {len(relationships)} relationships.")

    # Write relationships.csv
    rel_csv_path = os.path.join(OUTPUT_DIR, "relationships.csv")
    with open(rel_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "relationship_id", "source_id", "target_id", "relationship_type",
            "privilege_level", "risk_score", "confidence", "discovered_by",
            "timestamp", "description"
        ])
        writer.writeheader()
        writer.writerows(relationships)

    # =========================================================================
    # 3. ASSETS (35 Assets)
    # =========================================================================
    assets = []
    asset_node_candidates = [n for n in nodes if n["node_type"] in ["DATABASE", "SERVER", "APPLICATION", "STORAGE", "CLOUD_RESOURCE"]][:35]

    for idx, n in enumerate(asset_node_candidates):
        ast_id = f"ast-{idx+1:03d}"
        is_pci = "payment" in n["name"].lower() or "card" in n["name"].lower() or "ledger" in n["name"].lower()
        is_auth = "auth" in n["name"].lower() or "vault" in n["name"].lower() or "idp" in n["name"].lower()
        assets.append({
            "asset_id": ast_id,
            "node_id": n["node_id"],
            "asset_name": n["name"],
            "asset_type": n["node_type"],
            "criticality": n["criticality"],
            "business_owner": n["department"] + " Team Lead",
            "business_unit": n["department"],
            "business_value": n["business_value"],
            "confidentiality": "CRITICAL" if (is_pci or is_auth or n["criticality"] >= 0.9) else "HIGH",
            "integrity": "CRITICAL" if (is_pci or n["criticality"] >= 0.85) else "HIGH",
            "availability": "MISSION_CRITICAL" if n["criticality"] >= 0.9 else "HIGH",
            "internet_exposed": "true" if n["exposure"] == "INTERNET_FACING" else "false",
            "operational_status": "OPERATIONAL" if n["security_status"] != "COMPROMISED" else "AT_RISK",
            "recovery_priority": 1 if n["criticality"] >= 0.9 else (2 if n["criticality"] >= 0.7 else 3),
            "description": n["description"]
        })

    print(f"  [OK] Generated {len(assets)} assets.")
    assets_csv_path = os.path.join(OUTPUT_DIR, "assets.csv")
    with open(assets_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "asset_id", "node_id", "asset_name", "asset_type", "criticality",
            "business_owner", "business_unit", "business_value", "confidentiality",
            "integrity", "availability", "internet_exposed", "operational_status",
            "recovery_priority", "description"
        ])
        writer.writeheader()
        writer.writerows(assets)

    # =========================================================================
    # 4. USERS (30 Users)
    # =========================================================================
    users = []
    for u in user_data:
        users.append({
            "user_id": u[0],
            "node_id": u[1],
            "username": u[3],
            "role": u[5],
            "department": u[4],
            "privilege_level": u[6],
            "account_type": u[7],
            "mfa_enabled": "true" if u[7] != "SERVICE_ACCOUNT" and u[0] != "usr-010" else "false",
            "account_status": "LOCKED" if u[1] == "node-user-marcus" else ("ACTIVE" if u[9] == "HEALTHY" else "UNDER_INVESTIGATION"),
            "risk_score": round(u[8] * 100.0, 1),
            "last_login": (BASE_TIME - timedelta(hours=random.randint(1, 48))).isoformat(),
            "is_service_account": "true" if u[7] == "SERVICE_ACCOUNT" else "false"
        })

    print(f"  [OK] Generated {len(users)} users.")
    users_csv_path = os.path.join(OUTPUT_DIR, "users.csv")
    with open(users_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "user_id", "node_id", "username", "role", "department", "privilege_level",
            "account_type", "mfa_enabled", "account_status", "risk_score", "last_login",
            "is_service_account"
        ])
        writer.writeheader()
        writer.writerows(users)

    # =========================================================================
    # 5. VULNERABILITIES (45 Vulnerabilities)
    # =========================================================================
    vulnerabilities = []
    vuln_templates = [
        ("CVE-2024-21626", "runc Container Escape via file descriptor leak", "CRITICAL", 9.8, "FUNCTIONAL_POC", "Upgrade runc container runtime to v1.1.12+"),
        ("CVE-2023-44487", "HTTP/2 Rapid Reset Denial of Service Stream Multiplexing", "HIGH", 7.5, "HIGH", "Enable rate limiting and apply web server security patch"),
        ("CVE-2023-38606", "Linux Kernel Local Privilege Escalation via memory fault", "HIGH", 8.2, "FUNCTIONAL_POC", "Apply updated kernel security package and reboot"),
        ("CVE-2024-3094", "XZ Utils Liblzma Malicious Backdoor in OpenSSH daemon", "CRITICAL", 10.0, "HIGH", "Downgrade xz-utils to clean upstream release 5.4.6"),
        ("CVE-2023-48795", "SSH Terrapin Prefix Truncation Vulnerability", "MEDIUM", 5.9, "HIGH", "Disable chacha20-poly1305 and encrypt-then-mac MACs in sshd_config"),
        ("SYNTH-CVE-2026-1042", "Insecure Deserialization in Java Payment Processing Daemon", "CRITICAL", 9.4, "FUNCTIONAL_POC", "Migrate deserialization routines to strict Jackson JSON parser"),
        ("SYNTH-CVE-2026-1043", "Overly Permissive S3 Bucket ACL in Terraform Cloud Config", "HIGH", 7.8, "UNPROVEN", "Apply AWS IAM principle of least privilege and enable block public access"),
        ("SYNTH-CVE-2026-1044", "Hardcoded Bastion SSH Host Keys in Base VM Image", "CRITICAL", 9.1, "HIGH", "Regenerate unique host RSA/ED25519 keys via Cloud-Init"),
        ("SYNTH-CVE-2026-1045", "Cross-Site Scripting (Stored) in Citizen Services Portal", "MEDIUM", 6.1, "UNPROVEN", "Sanitize all user-submitted markdown payloads with DOMPurify"),
        ("SYNTH-CVE-2026-1046", "Unauthenticated Redis Command Injection via Internal Mesh", "HIGH", 8.6, "FUNCTIONAL_POC", "Enforce redis AUTH with TLS and bind strictly to localhost"),
    ]

    for idx in range(1, 46):
        tpl = vuln_templates[(idx - 1) % len(vuln_templates)]
        ast = assets[(idx - 1) % len(assets)]
        vid = f"vuln-{idx:03d}"
        vulnerabilities.append({
            "vulnerability_id": vid,
            "asset_id": ast["asset_id"],
            "cve_id": f"{tpl[0]}-{idx}" if "SYNTH" in tpl[0] else tpl[0],
            "title": f"{tpl[1]} (Target: {ast['asset_name']})",
            "severity": tpl[2],
            "cvss_score": tpl[3],
            "exploitability": tpl[4],
            "remediation_status": "OPEN" if idx in [1, 2, 3, 4, 10] else "IN_PROGRESS",
            "patch_available": "true" if idx % 4 != 0 else "false",
            "evidence_source": "Tenable_Nessus" if idx % 2 == 0 else "CrowdStrike_Spotlight",
            "discovered_at": (BASE_TIME - timedelta(days=idx)).isoformat(),
            "description": f"Vulnerability detected on asset {ast['asset_id']} ({ast['asset_name']}). {tpl[1]}",
            "remediation": tpl[5]
        })

    print(f"  [OK] Generated {len(vulnerabilities)} vulnerabilities.")
    vuln_csv_path = os.path.join(OUTPUT_DIR, "vulnerabilities.csv")
    with open(vuln_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "vulnerability_id", "asset_id", "cve_id", "title", "severity",
            "cvss_score", "exploitability", "remediation_status", "patch_available",
            "evidence_source", "discovered_at", "description", "remediation"
        ])
        writer.writeheader()
        writer.writerows(vulnerabilities)

    # =========================================================================
    # 6. SECURITY ALERTS (60 Alerts)
    # =========================================================================
    alerts = []
    alert_types = [
        ("SUSPICIOUS_LOGIN", "Unusual after-hours login detected from unexpected geographic subnet", "HIGH", 0.92),
        ("PRIVILEGE_ESCALATION", "Process spawned with elevated root UID from non-standard binary", "CRITICAL", 0.98),
        ("LATERAL_MOVEMENT", "Pass-the-hash authentication attempt observed over internal SMB", "CRITICAL", 0.95),
        ("MALWARE_EXECUTION", "Behavioral detection of memory-resident staging shellcode", "CRITICAL", 0.99),
        ("EXFILTRATION_INDICATOR", "High-frequency egress requests toward unrecognized external IP", "HIGH", 0.88),
        ("CREDENTIAL_DUMPING", "Attempted extraction of LSASS process memory handles", "CRITICAL", 0.96),
        ("PORT_SCAN", "Reconnaissance TCP SYN sweep across internal database VLAN", "MEDIUM", 0.85),
        ("UNUSUAL_API_VOLUME", "API invocation rate spiked 400% above moving baseline average", "MEDIUM", 0.78),
    ]

    for idx in range(1, 61):
        at = alert_types[(idx - 1) % len(alert_types)]
        aid = f"alrt-{idx:03d}"
        
        # Scenario 1 alerts
        if idx == 1:
            src_n = "node-user-marcus"
            tgt_n = "node-ep-laptop-marcus"
            desc = "Suspicious interactive developer session from unauthorized IP"
            path_ref = "path-001"
            v_ref = "vuln-001"
        elif idx == 2:
            src_n = "node-ep-laptop-marcus"
            tgt_n = "node-srv-jumpbox01"
            desc = "Lateral SSH movement from Marcus laptop to Production Jumpbox Bastion"
            path_ref = "path-001"
            v_ref = "vuln-002"
        elif idx == 3:
            src_n = "node-srv-jumpbox01"
            tgt_n = "node-app-payment-gateway"
            desc = "Privileged escalation on Bastion initiating admin tunnel to Payment Gateway"
            path_ref = "path-001"
            v_ref = "vuln-003"
        elif idx == 4:
            src_n = "node-app-payment-gateway"
            tgt_n = "node-db-customer-core"
            desc = "Automated bulk table query attempt targeting Customer Core PII database"
            path_ref = "path-001"
            v_ref = "vuln-004"
        else:
            src_n = random.choice([n["node_id"] for n in nodes if "node-ep-" in n["node_id"] or "node-user-" in n["node_id"]])
            tgt_n = random.choice([n["node_id"] for n in nodes if "node-srv-" in n["node_id"] or "node-db-" in n["node_id"]])
            desc = f"{at[0]} flagged between {src_n} and {tgt_n}: {at[1]}"
            path_ref = f"path-{(idx % 10) + 1:03d}"
            v_ref = f"vuln-{(idx % 45) + 1:03d}"

        alerts.append({
            "alert_id": aid,
            "timestamp": (BASE_TIME + timedelta(minutes=idx * 15)).isoformat(),
            "alert_type": at[0],
            "severity": at[2],
            "source_node_id": src_n,
            "target_node_id": tgt_n,
            "description": desc,
            "confidence": at[3],
            "status": "ACTIVE" if idx <= 10 else ("INVESTIGATING" if idx <= 30 else "TRIAGED"),
            "detection_source": "CrowdStrike_Falcon" if idx % 2 == 0 else "Splunk_ES",
            "related_vulnerability_id": v_ref,
            "related_attack_path_id": path_ref
        })

    print(f"  [OK] Generated {len(alerts)} security alerts.")
    alerts_csv_path = os.path.join(OUTPUT_DIR, "security_alerts.csv")
    with open(alerts_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "alert_id", "timestamp", "alert_type", "severity", "source_node_id",
            "target_node_id", "description", "confidence", "status", "detection_source",
            "related_vulnerability_id", "related_attack_path_id"
        ])
        writer.writeheader()
        writer.writerows(alerts)

    # =========================================================================
    # 7. EVIDENCE (75 Records)
    # =========================================================================
    evidence = []
    statuses = ["CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "UNKNOWN"]
    types = ["EDR_PROCESS_LINE", "NETWORK_FLOW_SESSION", "AUDIT_LOG_ENTRY", "AUTHENTICATION_RECORD", "FILE_INTEGRITY_ALERT"]

    for idx in range(1, 76):
        eid = f"ev-{idx:03d}"
        stat = "CONFIRMED" if idx <= 35 else ("SUSPECTED" if idx <= 55 else ("INCONCLUSIVE" if idx <= 68 else "UNKNOWN"))
        node_id = nodes[(idx - 1) % len(nodes)]["node_id"]
        alert_id = alerts[(idx - 1) % len(alerts)]["alert_id"]
        vuln_id = vulnerabilities[(idx - 1) % len(vulnerabilities)]["vulnerability_id"]

        evidence.append({
            "evidence_id": eid,
            "evidence_type": types[(idx - 1) % len(types)],
            "related_node_id": node_id,
            "related_alert_id": alert_id,
            "related_vulnerability_id": vuln_id,
            "source": "CrowdStrike_Sensor" if idx % 2 == 0 else "Splunk_Universal_Forwarder",
            "observation": f"Forensic observation [{stat}] on node {node_id}: telemetry correlates with alert {alert_id}",
            "confidence": 0.95 if stat == "CONFIRMED" else (0.65 if stat == "SUSPECTED" else (0.40 if stat == "INCONCLUSIVE" else 0.20)),
            "reliability": 0.98 if stat == "CONFIRMED" else (0.75 if stat == "SUSPECTED" else 0.50),
            "timestamp": (BASE_TIME + timedelta(minutes=idx * 12)).isoformat(),
            "evidence_status": stat
        })

    print(f"  [OK] Generated {len(evidence)} evidence records.")
    evidence_csv_path = os.path.join(OUTPUT_DIR, "evidence.csv")
    with open(evidence_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "evidence_id", "evidence_type", "related_node_id", "related_alert_id",
            "related_vulnerability_id", "source", "observation", "confidence",
            "reliability", "timestamp", "evidence_status"
        ])
        writer.writeheader()
        writer.writerows(evidence)

    # =========================================================================
    # 8. ATTACK PATHS (32 Records)
    # =========================================================================
    attack_paths = []

    # Path 1: Primary Judge Demo (Marcus -> Laptop -> Jumpbox01 -> Payment Gateway -> Customer Core DB)
    attack_paths.append({
        "attack_path_id": "path-001",
        "scenario_id": "SCEN-001",
        "entry_node_id": "node-user-marcus",
        "target_node_id": "node-db-customer-core",
        "path_nodes": "node-user-marcus;node-ep-laptop-marcus;node-srv-jumpbox01;node-app-payment-gateway;node-db-customer-core",
        "path_relationships": f"{r_m1};{r_m2};{r_m3};{r_m4}",
        "path_length": 4,
        "severity": "CRITICAL",
        "likelihood": 0.92,
        "impact": 98.0,
        "risk_score": 90.2,
        "confidence": 0.94,
        "status": "ACTIVE"
    })

    # Path 2: Alternative route for Marcus (Marcus -> Laptop -> VPN -> Staging API -> Jumpbox02 -> Customer Core DB)
    attack_paths.append({
        "attack_path_id": "path-002",
        "scenario_id": "SCEN-001",
        "entry_node_id": "node-user-marcus",
        "target_node_id": "node-db-customer-core",
        "path_nodes": "node-user-marcus;node-ep-laptop-marcus;node-srv-vpn-concentrator;node-srv-staging-api;node-srv-jumpbox02;node-db-customer-core",
        "path_relationships": f"{r_m1};{r_m5};{r_m6};{r_m7};{r_m8}",
        "path_length": 5,
        "severity": "HIGH",
        "likelihood": 0.75,
        "impact": 95.0,
        "risk_score": 71.3,
        "confidence": 0.78,
        "status": "POTENTIAL"
    })

    # Path 3: External Web Attack to Identity Vault (Scenario 2)
    attack_paths.append({
        "attack_path_id": "path-003",
        "scenario_id": "SCEN-002",
        "entry_node_id": "node-net-fw-perimeter",
        "target_node_id": "node-db-id-vault",
        "path_nodes": "node-net-fw-perimeter;node-srv-web-public;node-app-citizen-portal;node-srv-api-gateway;node-app-auth-service;node-db-id-vault",
        "path_relationships": f"{r_e1};{r_e2};{r_e3};{r_e4};{r_e5}",
        "path_length": 5,
        "severity": "CRITICAL",
        "likelihood": 0.88,
        "impact": 100.0,
        "risk_score": 88.0,
        "confidence": 0.95,
        "status": "ACTIVE"
    })

    # Path 4: Cloud CI/CD Supply Chain to Payment Ledger (Scenario 3)
    attack_paths.append({
        "attack_path_id": "path-004",
        "scenario_id": "SCEN-003",
        "entry_node_id": "node-user-svc-cicd",
        "target_node_id": "node-db-payment-ledger",
        "path_nodes": "node-user-svc-cicd;node-srv-gitlab;node-srv-k8s-master01;node-cld-iam-role;node-cld-s3-lake;node-db-payment-ledger",
        "path_relationships": f"{r_c1};{r_c2};{r_c3};{r_c4};{r_c5}",
        "path_length": 5,
        "severity": "CRITICAL",
        "likelihood": 0.85,
        "impact": 99.0,
        "risk_score": 84.1,
        "confidence": 0.91,
        "status": "ACTIVE"
    })

    # Generate Paths 5 through 32 systematically along real graph edges
    for idx in range(5, 33):
        pid = f"path-{idx:03d}"
        scen_id = f"SCEN-{(idx % 10) + 1:03d}"
        # Pick real relationships from list
        start_rel = relationships[idx * 3]
        second_rel = relationships[idx * 3 + 1]
        sev = "CRITICAL" if idx <= 12 else ("HIGH" if idx <= 24 else "MEDIUM")
        lik = round(random.uniform(0.60, 0.90), 2)
        imp = round(random.uniform(65.0, 95.0), 1)
        
        attack_paths.append({
            "attack_path_id": pid,
            "scenario_id": scen_id,
            "entry_node_id": start_rel["source_id"],
            "target_node_id": second_rel["target_id"] if second_rel["target_id"] != start_rel["source_id"] else "node-db-customer-core",
            "path_nodes": f"{start_rel['source_id']};{start_rel['target_id']};{second_rel['target_id']}",
            "path_relationships": f"{start_rel['relationship_id']};{second_rel['relationship_id']}",
            "path_length": 2,
            "severity": sev,
            "likelihood": lik,
            "impact": imp,
            "risk_score": round(lik * imp, 1),
            "confidence": round(random.uniform(0.70, 0.96), 2),
            "status": "ACTIVE" if idx <= 18 else "POTENTIAL"
        })

    print(f"  [OK] Generated {len(attack_paths)} attack paths.")
    paths_csv_path = os.path.join(OUTPUT_DIR, "attack_paths.csv")
    with open(paths_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "attack_path_id", "scenario_id", "entry_node_id", "target_node_id",
            "path_nodes", "path_relationships", "path_length", "severity",
            "likelihood", "impact", "risk_score", "confidence", "status"
        ])
        writer.writeheader()
        writer.writerows(attack_paths)

    # =========================================================================
    # 9. INTERVENTIONS (45 Actions)
    # =========================================================================
    interventions = [
        # Scenario 1 core interventions
        {
            "intervention_id": "act-001",
            "action_name": "Isolate Marcus Vance Laptop (CrowdStrike)",
            "action_type": "ISOLATE_ENDPOINT",
            "target_node_id": "node-ep-laptop-marcus",
            "target_relationship_id": r_m1,
            "expected_risk_reduction": 90.0,
            "implementation_cost": 1500.0,
            "business_disruption": 5.0,
            "implementation_time": 5,
            "reversibility": "true",
            "requires_approval": "false",
            "description": "Trigger EDR network containment on Marcus laptop to sever lateral C2 and SSH tunnels",
            "justification": "Primary choke point for Scenario 1; terminates path-001 and path-002 without impacting backend services"
        },
        {
            "intervention_id": "act-002",
            "action_name": "Disable Marcus Vance Identity (Okta)",
            "action_type": "DISABLE_ACCOUNT",
            "target_node_id": "node-user-marcus",
            "target_relationship_id": r_m1,
            "expected_risk_reduction": 85.0,
            "implementation_cost": 500.0,
            "business_disruption": 2.0,
            "implementation_time": 3,
            "reversibility": "true",
            "requires_approval": "false",
            "description": "Revoke active Okta sessions, invalidate refresh tokens, and suspend Active Directory account",
            "justification": "Prevents attacker from re-authenticating via VPN or alternative endpoints"
        },
        {
            "intervention_id": "act-003",
            "action_name": "Sever Payment Gateway Internal Firewall (Disruptive)",
            "action_type": "APPLY_FIREWALL_RULE",
            "target_node_id": "node-app-payment-gateway",
            "target_relationship_id": r_m4,
            "expected_risk_reduction": 98.0,
            "implementation_cost": 12000.0,
            "business_disruption": 95.0,
            "implementation_time": 20,
            "reversibility": "true",
            "requires_approval": "true",
            "description": "Apply immediate emergency network drop rule blocking all traffic into Payment Gateway microservice",
            "justification": "Disruptive nuclear option: stops breach but inflicts $120,000/hr outage on citizen payment pipeline"
        },
        {
            "intervention_id": "act-004",
            "action_name": "Rotate Jumpbox Bastion SSH Host Keys & Force Re-Auth",
            "action_type": "ROTATE_CREDENTIALS",
            "target_node_id": "node-srv-jumpbox01",
            "target_relationship_id": r_m2,
            "expected_risk_reduction": 80.0,
            "implementation_cost": 2500.0,
            "business_disruption": 10.0,
            "implementation_time": 15,
            "reversibility": "true",
            "requires_approval": "false",
            "description": "Rotate SSH authorized_keys and invalidate cached agent keys on primary Bastion host",
            "justification": "Eliminates reused SSH credential pivot without shutting down developer infrastructure"
        },
    ]

    action_types = [
        "ISOLATE_ENDPOINT", "DISABLE_ACCOUNT", "REVOKE_SESSION", "ROTATE_CREDENTIALS",
        "APPLY_FIREWALL_RULE", "PATCH_VULNERABILITY", "RESTRICT_RESOURCE_ACCESS", "ENFORCE_MFA"
    ]

    for idx in range(5, 46):
        aid = f"act-{idx:03d}"
        at = action_types[(idx - 1) % len(action_types)]
        tgt_node = nodes[(idx * 2) % len(nodes)]
        rel_ref = relationships[(idx * 3) % len(relationships)]["relationship_id"]
        is_expensive = (idx % 5 == 0)

        interventions.append({
            "intervention_id": aid,
            "action_name": f"{at.replace('_', ' ').title()} on {tgt_node['name']}",
            "action_type": at,
            "target_node_id": tgt_node["node_id"],
            "target_relationship_id": rel_ref,
            "expected_risk_reduction": round(random.uniform(50.0, 92.0), 1),
            "implementation_cost": round(random.uniform(15000.0, 35000.0) if is_expensive else random.uniform(800.0, 4500.0), 2),
            "business_disruption": round(random.uniform(70.0, 95.0) if is_expensive else random.uniform(5.0, 25.0), 1),
            "implementation_time": random.randint(5, 60),
            "reversibility": "true" if idx % 7 != 0 else "false",
            "requires_approval": "true" if is_expensive else "false",
            "description": f"Automated intervention executing {at} targeting {tgt_node['name']}",
            "justification": f"Mitigates attack path exposure involving node {tgt_node['node_id']}"
        })

    print(f"  [OK] Generated {len(interventions)} interventions.")
    interv_csv_path = os.path.join(OUTPUT_DIR, "interventions.csv")
    with open(interv_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "intervention_id", "action_name", "action_type", "target_node_id",
            "target_relationship_id", "expected_risk_reduction", "implementation_cost",
            "business_disruption", "implementation_time", "reversibility",
            "requires_approval", "description", "justification"
        ])
        writer.writeheader()
        writer.writerows(interventions)

    # =========================================================================
    # 10. ASSET DEPENDENCIES (60 Records)
    # =========================================================================
    dependencies = []
    dep_types = ["DATA_FEED", "AUTHENTICATION", "API_CALL", "REPLICATION", "BACKUP", "TELEMETRY"]

    for idx in range(1, 61):
        did = f"dep-{idx:03d}"
        src_ast = assets[(idx - 1) % len(assets)]
        dep_ast = assets[(idx * 2) % len(assets)]
        if src_ast["asset_id"] == dep_ast["asset_id"]:
            dep_ast = assets[(idx * 2 + 1) % len(assets)]

        dependencies.append({
            "dependency_id": did,
            "source_asset_id": src_ast["asset_id"],
            "dependent_asset_id": dep_ast["asset_id"],
            "dependency_type": dep_types[(idx - 1) % len(dep_types)],
            "dependency_strength": round(random.uniform(0.60, 0.99), 2),
            "business_impact": "CRITICAL_OUTAGE" if idx <= 15 else ("DEGRADED_PERFORMANCE" if idx <= 35 else "OPERATIONAL_SLOWNESS"),
            "availability_requirement": "99.999%" if idx <= 15 else ("99.99%" if idx <= 40 else "99.0%"),
            "description": f"Service dependency: {src_ast['asset_name']} relies on {dep_ast['asset_name']} for {dep_types[(idx - 1) % len(dep_types)]}"
        })

    print(f"  [OK] Generated {len(dependencies)} asset dependencies.")
    dep_csv_path = os.path.join(OUTPUT_DIR, "asset_dependencies.csv")
    with open(dep_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "dependency_id", "source_asset_id", "dependent_asset_id", "dependency_type",
            "dependency_strength", "business_impact", "availability_requirement", "description"
        ])
        writer.writeheader()
        writer.writerows(dependencies)

    # =========================================================================
    # 11. BUSINESS IMPACT (35 Records)
    # =========================================================================
    impact_functions = [
        ("Instant Payments Processing", 120000.0, "0 hours", "15 minutes", "0 seconds (Sync)", "PCI-DSS Non-Compliance", "TRANSACTION_FAILURES", "SEVERE", 98.0),
        ("Citizen Identity Verification", 85000.0, "0 hours", "30 minutes", "1 minute", "GDPR Fine Risk", "HIGH_VISIBILITY_OUTAGE", "SEVERE", 92.0),
        ("Core Account Ledger Settlement", 95000.0, "1 hour", "1 hour", "5 minutes", "SOX Audit Exception", "TRANSACTION_FAILURES", "SEVERE", 95.0),
        ("Emergency Breakglass Access", 45000.0, "0 hours", "15 minutes", "0 seconds (Sync)", "Regulatory Audit Notice", "LOW_INTERNAL_ONLY", "MODERATE", 85.0),
        ("Daily Automated Payroll Distribution", 60000.0, "4 hours", "2 hours", "1 hour", "Labor Regulatory Fine", "CUSTOMER_CHURN", "SEVERE", 88.0),
        ("Citizen Healthcare Records Lookup", 75000.0, "0 hours", "15 minutes", "0 seconds (Sync)", "HIPAA Penalty", "HIGH_VISIBILITY_OUTAGE", "SEVERE", 94.0),
        ("Corporate Email & Communication", 15000.0, "4 hours", "4 hours", "4 hours", "Minor Compliance", "LOW_INTERNAL_ONLY", "MINOR", 50.0),
        ("Customer Facing Web Portal Frontend", 40000.0, "1 hour", "1 hour", "15 minutes", "Brand Damage", "HIGH_VISIBILITY_OUTAGE", "MODERATE", 75.0),
    ]

    business_impacts = []
    for idx, ast in enumerate(assets):
        imp = impact_functions[idx % len(impact_functions)]
        business_impacts.append({
            "impact_id": f"imp-{idx+1:03d}",
            "asset_id": ast["asset_id"],
            "business_function": f"{imp[0]} ({ast['asset_name']})",
            "estimated_hourly_loss": imp[1],
            "downtime_tolerance": imp[2],
            "recovery_time_objective": imp[3],
            "recovery_point_objective": imp[4],
            "regulatory_impact": imp[5],
            "customer_impact": imp[6],
            "operational_impact": imp[7],
            "impact_score": imp[8]
        })

    print(f"  [OK] Generated {len(business_impacts)} business impact records.")
    impact_csv_path = os.path.join(OUTPUT_DIR, "business_impact.csv")
    with open(impact_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "impact_id", "asset_id", "business_function", "estimated_hourly_loss",
            "downtime_tolerance", "recovery_time_objective", "recovery_point_objective",
            "regulatory_impact", "customer_impact", "operational_impact", "impact_score"
        ])
        writer.writeheader()
        writer.writerows(business_impacts)

    # =========================================================================
    # 12. THREAT SCENARIOS (10 Scenarios)
    # =========================================================================
    threat_scenarios = [
        {
            "scenario_id": "SCEN-001",
            "scenario_name": "Compromised Developer Account to Customer PII Database",
            "scenario_category": "INSIDER_COMPROMISE",
            "entry_node_id": "node-user-marcus",
            "target_node_id": "node-db-customer-core",
            "threat_description": "Marcus Vance developer laptop compromised via drive-by phish; cached Bastion SSH keys leveraged to pivot into production Payment Gateway and access Customer Core PII.",
            "initial_risk": 90.2,
            "expected_outcome": "EDR isolation of laptop + account disable neutralizes threat with 95% risk reduction and zero workflow disruption, avoiding disruptive firewall drop.",
            "recommended_interventions": "act-001;act-002",
            "difficulty": "DEMO_CORE",
            "demo_description": "Primary Judge Demo Scenario: shows multi-hop graph traversal, risk decomposition, business disruption trade-off, and CP-SAT containment optimization."
        },
        {
            "scenario_id": "SCEN-002",
            "scenario_name": "Perimeter Web Exploit to Sovereign Identity Vault",
            "scenario_category": "EXTERNAL_EXPLOIT",
            "entry_node_id": "node-net-fw-perimeter",
            "target_node_id": "node-db-id-vault",
            "threat_description": "Unauthenticated external adversary exploits public Nginx reverse proxy, pivoting through API Gateway to tamper with Sovereign Identity credentials.",
            "initial_risk": 88.0,
            "expected_outcome": "WAF rate limit rule + microsegmentation drop sever path before identity vault is breached.",
            "recommended_interventions": "act-004;act-005",
            "difficulty": "ADVANCED",
            "demo_description": "Demonstrates perimeter-to-core defense-in-depth and uncertainty-aware risk scoring."
        },
        {
            "scenario_id": "SCEN-003",
            "scenario_name": "Cloud CI/CD Supply Chain to Payment Ledger",
            "scenario_category": "CLOUD_CREDENTIAL_LEAK",
            "entry_node_id": "node-user-svc-cicd",
            "target_node_id": "node-db-payment-ledger",
            "threat_description": "GitLab CI service account token exfiltrated; attacker assumes AWS SuperAdmin IAM role to access S3 data lake and tamper with payment ledger archives.",
            "initial_risk": 84.1,
            "expected_outcome": "IAM role privilege boundary revocation isolates cloud bucket without interrupting live microservices.",
            "recommended_interventions": "act-006;act-007",
            "difficulty": "ADVANCED",
            "demo_description": "Demonstrates cloud IAM graph traversal and hybrid multi-cloud dependency analysis."
        },
        {
            "scenario_id": "SCEN-004",
            "scenario_name": "Privileged Administrator Credential Misuse",
            "scenario_category": "PRIVILEGED_ESCALATION",
            "entry_node_id": "node-user-sarah",
            "target_node_id": "node-srv-vault01",
            "threat_description": "DevOps administrator credentials leveraged from unusual subnet outside operational change window to dump secret vault master keys.",
            "initial_risk": 86.5,
            "expected_outcome": "Enforce immediate MFA step-up and revoke active Bastion tokens, preventing vault extraction.",
            "recommended_interventions": "act-008;act-009",
            "difficulty": "ADVANCED",
            "demo_description": "Demonstrates privileged identity containment and human-in-the-loop review approval."
        },
        {
            "scenario_id": "SCEN-005",
            "scenario_name": "Ransomware Pre-Execution Staging on File Transfer Server",
            "scenario_category": "RANSOMWARE_STAGING",
            "entry_node_id": "node-app-file-transfer",
            "target_node_id": "node-db-finance-ledger",
            "threat_description": "Vulnerable banking SFTP bridge infected with staging binary; attacker prepares to encrypt finance ERP database LUNs.",
            "initial_risk": 91.0,
            "expected_outcome": "Isolate SFTP bridge and trigger immutable WORM snapshot lock on Veeam repository.",
            "recommended_interventions": "act-010;act-011",
            "difficulty": "EXPERT",
            "demo_description": "Demonstrates rapid ransomware containment and immutable business recovery integration."
        },
        {
            "scenario_id": "SCEN-006",
            "scenario_name": "Third-Party QA Contractor VPN Lateral Pivot",
            "scenario_category": "SUPPLY_CHAIN_LATERAL",
            "entry_node_id": "node-user-tom",
            "target_node_id": "node-db-customer-core",
            "threat_description": "External QA contractor workstation infected; attacker attempts to leverage debug staging routes to cross into production database VLAN.",
            "initial_risk": 75.0,
            "expected_outcome": "Drop contractor VPN session and sever staging-to-prod inter-VLAN route.",
            "recommended_interventions": "act-012;act-013",
            "difficulty": "DEMO_CORE",
            "demo_description": "Demonstrates contractor segmentation enforcement and zero-trust policy verification."
        },
        {
            "scenario_id": "SCEN-007",
            "scenario_name": "Zero-Day Remote Code Execution on Internal API Gateway",
            "scenario_category": "ZERO_DAY_PIVOT",
            "entry_node_id": "node-srv-api-gateway",
            "target_node_id": "node-app-payment-gateway",
            "threat_description": "Zero-day vulnerability exploited on Kong gateway allowing arbitrary memory inspection and internal route poisoning.",
            "initial_risk": 89.5,
            "expected_outcome": "Deploy microsegmentation ACL and rotate gateway mTLS certificates.",
            "recommended_interventions": "act-014;act-015",
            "difficulty": "EXPERT",
            "demo_description": "Demonstrates zero-day mitigation via topological microsegmentation."
        },
        {
            "scenario_id": "SCEN-008",
            "scenario_name": "Uncertain Telemetry: Heuristic Lateral Anomaly",
            "scenario_category": "SUSPECTED_UNVERIFIED_THREAT",
            "entry_node_id": "node-ep-ws02",
            "target_node_id": "node-db-hr-records",
            "threat_description": "Unverified EDR heuristic alert flags potential Kerberoasting attack against Active Directory DC with low confidence (0.42).",
            "initial_risk": 68.0,
            "expected_outcome": "Increase monitoring level rather than disruptive host shutdown, validating uncertainty-aware response.",
            "recommended_interventions": "act-016;act-017",
            "difficulty": "DEMO_CORE",
            "demo_description": "Demonstrates Evidence Uncertainty tab and penalty weighting on suspected vs confirmed telemetry."
        },
        {
            "scenario_id": "SCEN-009",
            "scenario_name": "Multi-Path Coordinated Assault on Payment Infrastructure",
            "scenario_category": "MULTI_PATH_DATABASE_ASSAULT",
            "entry_node_id": "node-user-marcus",
            "target_node_id": "node-db-payment-ledger",
            "threat_description": "Adversary explores both internal Bastion jump hosts and external staging API simultaneously to reach payment ledger.",
            "initial_risk": 94.5,
            "expected_outcome": "Coordinated multi-action plan blocks both concurrent routes while preserving citizen card processing.",
            "recommended_interventions": "act-001;act-002;act-004",
            "difficulty": "EXPERT",
            "demo_description": "Demonstrates residual path detection when only one branch of an attack vector is cut."
        },
        {
            "scenario_id": "SCEN-010",
            "scenario_name": "High-Risk Threat Requiring Zero-Outage Containment",
            "scenario_category": "LOW_DISRUPTION_CONTAINMENT_CHALLENGE",
            "entry_node_id": "node-srv-staging-api",
            "target_node_id": "node-db-customer-core",
            "threat_description": "Staging server compromised during live citizen tax filing window; containment must guarantee 100% SLA uptime.",
            "initial_risk": 78.0,
            "expected_outcome": "Targeted token revocation achieves containment with $0 financial downtime impact.",
            "recommended_interventions": "act-002;act-018",
            "difficulty": "DEMO_CORE",
            "demo_description": "Demonstrates Business Continuity Twin SLA constraints in CP-SAT optimizer."
        },
    ]

    print(f"  [OK] Generated {len(threat_scenarios)} threat scenarios.")
    scen_csv_path = os.path.join(OUTPUT_DIR, "threat_scenarios.csv")
    with open(scen_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "scenario_id", "scenario_name", "scenario_category", "entry_node_id",
            "target_node_id", "threat_description", "initial_risk", "expected_outcome",
            "recommended_interventions", "difficulty", "demo_description"
        ])
        writer.writeheader()
        writer.writerows(threat_scenarios)

    print("\nDataset Generation Complete! 12 CSV files written to:")
    print(f"  {OUTPUT_DIR}")


if __name__ == "__main__":
    generate_all()
