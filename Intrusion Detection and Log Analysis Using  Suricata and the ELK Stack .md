
# Intrusion Detection and Log Analysis Using Suricata and the ELK Stack

## A Project Report

**Submitted by:**  
**Mohammed Ramees T**  

RedTeam Hacker Academy  
 
CICSA (Certified IT Infrastructure and Cyber SOC Analyst)  
in Cyber Security 
 
<img width="707" height="211" alt="image" src="https://github.com/user-attachments/assets/498c45f3-1cc7-4ab8-a1d5-8776c1a75bbf" />

---

## Table of Contents

- [Introduction](#1-introduction)  
  - [1.1 Background](#11-background)  
  - [1.2 Motivation](#12-motivation)  
  - [1.3 Project Overview](#13-project-overview)  
  - [1.4 Objectives](#14-objectives)  
- [Environment and Tools](#2-environment-and-tools)  
  - [2.1 System Environment](#21-system-environment)  
  - [2.2 Tools and Technologies Used](#22-tools-and-technologies-used)  
- [Implementation](#3-implementation)  
  - [3.1 Install Suricata](#31-install-suricata)  
  - [3.2 Install Elasticsearch](#32-install-elasticsearch)  
  - [3.3 Install Filebeat](#33-install-filebeat)  
  - [3.4 Install Logstash](#34-install-logstash)  
  - [3.5 Install Kibana](#35-install-kibana)  
  - [3.6 Integration Steps](#36-integration-steps)  
  - [3.7 Install OpenSSH Server](#37-install-openssh-server)  
  - [3.8 Attacks Performed](#38-attacks-performed)  
  - [3.9 Detection](#39-detection)  
  - [3.10 Kibana Log Overview](#310-kibana-log-overview)  
- [Results and Observations](#4-results-and-observations)  
  - [4.1 Project Summary](#41-project-summary)  
  - [4.2 Conclusion and Future Scope](#42-conclusion-and-future-scope)  

---

## 1 Introduction

### 1.1 Background
In today’s cybersecurity landscape, organizations face increasing threats like unauthorized access, brute-force login attempts, and data exfiltration. Without the right monitoring and analysis tools, these attacks often go undetected. Intrusion Detection Systems (IDS) such as Suricata detect malicious activity in real-time by inspecting network traffic against a set of predefined rules. However, managing raw alert data at scale is difficult. The ELK Stack (Elasticsearch, Logstash, Kibana) addresses this by collecting, indexing, and visualizing logs in a human-readable format. When used together, these tools create an efficient and scalable Network Security Monitoring (NSM) solution.

### 1.2 Motivation
The main motivation for this project was to gain hands-on experience with industry-standard cybersecurity tools. As part of the Certified Information Cyber Security Analyst (CICSA) course, the goal was to understand how real-time traffic inspection works, detect attacks like brute force login attempts, and visualize threats for better incident response. The project aimed to replicate the functionality of a Security Operations Center (SOC) using open-source tools and simulated attacks.

### 1.3 Objectives

- Install and configure Suricata IDS on a Ubuntu system to monitor incoming network traffic.
- Simulate an SSH brute-force attack using Hydra to create real-world detection scenarios.
- Create a custom Suricata rule to trigger alerts for repeated failed SSH login attempts.
- Use Filebeat and Logstash to collect and process Suricata-generated logs.
- Visualize detected attacks in Kibana with real-time dashboards.
- Gain hands-on experience with the ELK Stack for log management and analysis.
- Understand the workflow of a SOC in detecting and analyzing security incidents.

## 2 Environment and Tools

### 2.1 System Environment

- **Host OS**: Windows 11  
- **Virtualization Platform**: VirtualBox 7.1.6  
- **Guest VMs**: Kali Linux (Attacker Machine), Ubuntu 22.04 (Suricata + ELK Stack)  

### 2.2 Tools and Technologies Used

| Tool         | Description                        |
|--------------|------------------------------------|
| Suricata     | Network IDS/IPS                    |
| Elasticsearch| Log storage and search engine      |
| Logstash     | Data collection and transformation |
| Kibana       | Visualization and dashboard tool   |

### 2.2.1 Suricata

<img width="564" height="311" alt="image" src="https://github.com/user-attachments/assets/620d65c3-d1e4-4ce2-a84e-bdb622b17b7c" />

Suricata is a powerful, open-source network threat detection engine that functions as both an Intrusion Detection System (IDS) and an Intrusion Prevention System (IPS). It is a high-performance tool widely adopted by both private and public organizations.

In simple terms, Suricata is like a digital security guard for computer networks. It carefully watches the traffic moving through the network, looking for any signs of suspicious or harmful activity. It helps keep the network safe by identifying and alerting to potential threats, making it a valuable tool for protecting digital assets.

---

### 2.2.2 Working of Suricata

<img width="709" height="291" alt="image" src="https://github.com/user-attachments/assets/584b4a9c-db1a-49b8-b1d2-86e696b8ded1" />

Suricata monitors network traffic using **signature-based** and **anomaly-based** detection methods. It can generate alerts and logs for system administrators and block threats when running in **IPS mode**.

**Key Features:**

- **Packet Capture & Decoding**: Captures network packets and decodes their content to understand communication protocols.
- **Signature-Based Detection**: Identifies known threats by comparing traffic against a database of malicious patterns (like antivirus software).
- **Anomaly-Based Detection**: Detects unknown or emerging threats by identifying deviations from normal network behavior.
- **Logging & Alerting**: Generates detailed logs and alerts for administrators when suspicious activity is found.
- **Blocking (IPS Mode)**: In IPS mode, Suricata can actively block malicious traffic in real-time.
- **Deployment Flexibility**: Can be deployed at various network points—perimeter, internal segments, or cloud-based.
- **Configurable Rule Sets**: Detection and response capabilities are customizable through rule sets.
- **Regular Updates**: Requires frequent updates to stay effective against evolving threats.

---

### 2.2.3 ELK Stack (Elasticsearch, Logstash, and Kibana)

The **ELK Stack** is a widely used, open-source suite for **centralized logging**, **search**, and **data visualization**. It is a powerful combination for monitoring, troubleshooting, and analyzing large volumes of log data.
<img width="940" height="265" alt="image" src="https://github.com/user-attachments/assets/38cd5af8-6c51-4036-a8ed-862015989b1c" />

#### 🔹 Logstash
- Ingests data from various sources (logs, databases, sensors, etc.)
- Transforms data (parsing, filtering, enriching)
- Forwards data to a "stash" (usually Elasticsearch)
<img width="545" height="337" alt="image" src="https://github.com/user-attachments/assets/a14ea17a-e86d-4e6d-8058-409fbfe1b199" />

#### 🔹 Elasticsearch
- Stores processed data (commonly in JSON format)
- Enables fast search and aggregation using an **inverted index**
- Supports real-time analytics across massive datasets

#### 🔹 Kibana
- Connects to Elasticsearch
- Provides interactive dashboards, charts, graphs, and maps
- Makes complex data easy to visualize and interpret
- Helps identify patterns, anomalies, and insights in real-time
  
<img width="636" height="356" alt="image" src="https://github.com/user-attachments/assets/09d05743-254a-4bb7-b408-21ab032d0e4f" />


## 3 Implementation

### 3.1 Install Suricata


```bash
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata

<img width="602" height="149" alt="image" src="https://github.com/user-attachments/assets/d5d3e871-aeb0-4638-8510-55e1da47f6c6" />


sudo systemctl status suricata
```
<img width="609" height="198" alt="image" src="https://github.com/user-attachments/assets/91e05154-f420-48d3-bc9b-5665968b27dd" />


Main configuration files location: `/etc/suricata/`

- `classification.config`: Categorizes detected events  
- `reference.config`: Provides threat reference info  
- `suricata.yaml`: Main configuration file  
- `threshold.config`: Controls alert flooding  

#### 3.1.1 Create Suricata Rules

Add the following rule to `/etc/suricata/rules/local.rules`:

```bash
alert ssh any any -> any any (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH"; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)
```

#### 3.1.2 Configure Suricata

Edit `suricata.yaml` to include the rule file and set output path.

Test config:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### 3.2 Install Elasticsearch

```bash
sudo apt install elasticsearch
sudo systemctl start elasticsearch
```

### 3.3 Install Filebeat

```bash
sudo apt install filebeat
```

Edit `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json

# Comment out Elasticsearch output
#output.elasticsearch:
#  hosts: ["localhost:9200"]

# Enable Logstash output
output.logstash:
  hosts: ["localhost:5044"]
```

Start and enable Filebeat:

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### 3.4 Install Logstash

```bash
sudo apt install logstash
```

#### 3.4.1 Logstash Pipeline Configuration

Create `/etc/logstash/conf.d/suricata.conf` and define pipeline.

Start Logstash:

```bash
sudo systemctl start logstash
```

### 3.5 Install Kibana

```bash
sudo apt install kibana
sudo systemctl start kibana
```

Access via: `http://localhost:5601`

### 3.6 Integration Steps

- Suricata logs to `/var/log/suricata/eve.json`
- Filebeat → Logstash → Elasticsearch  
- Kibana reads Elasticsearch and visualizes the alerts

### 3.7 Install OpenSSH Server

```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
```

### 3.8 Attacks Performed

SSH brute-force attack from Kali Linux using Hydra:

```bash
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://192.168.137.47
```

### 3.9 Detection

Suricata detects repeated SSH login failures and logs them.  
Alerts stored in `/var/log/suricata/eve.json`. Use `grep` to find alerts.

### 3.10 Kibana Log Overview

- Create index pattern (e.g., `filebeat-*`)  
- Use **Discover** to explore logs with filters like `alert.signature: "*Brute*"`  
- Build visualizations: top IPs, alerts over time  
- Combine into real-time dashboards  

## 4 Results and Observations

### 4.1 Project Summary

This project simulated and detected SSH brute-force attacks using Suricata and ELK Stack. Custom Suricata rules were used, logs were collected via Filebeat, parsed with Logstash, and visualized using Kibana dashboards.

### 4.2 Conclusion and Future Scope

- Demonstrated real-time alerting and visualization with open-source tools  
- Setup is ideal for small SOC or learning environments  

#### Future Improvements:

- Integrate **Zeek** for deeper packet inspection  
- Detect DNS tunneling, scans, web exploits  
- Automate alert response  
- Scale across multiple monitored hosts  

---

**Thanks for reading!**
