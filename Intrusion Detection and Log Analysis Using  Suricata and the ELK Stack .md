# Intrusion Detection and Log Analysis Using Suricata and the ELK Stack

CICSA (Certified IT Infrastructure and Cyber SOC Analyst)  
 
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

Execute the given commands to setup and install the latest Stable Suricata on Ubuntu.


```bash
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata

<img width="602" height="149" alt="image" src="https://github.com/user-attachments/assets/d5d3e871-aeb0-4638-8510-55e1da47f6c6" />


Once Suricata is installed, let’s now check if its running already by using the following command.
sudo systemctl status suricata
```
<img width="609" height="198" alt="image" src="https://github.com/user-attachments/assets/91e05154-f420-48d3-bc9b-5665968b27dd" />


As we can see that Suricata is already running
Now that Suricata is successfully installed, and its service is running successfully, let’s explore its configuration files located in the /etc/suricata/ directory.


<img width="940" height="235" alt="image" src="https://github.com/user-attachments/assets/641ca89a-6379-40ba-8f8c-a21cd30d2ed0" />


Here's a shortened explanation of the four essential Suricata configuration files:

- `classification.config`: Categorizes detected events  
- `reference.config`: Provides threat reference info  
- `suricata.yaml`: Main configuration file  
- `threshold.config`: Controls alert flooding  

#### 3.1.1 Create Suricata Rules

Add the following rule to `/etc/suricata/rules/local.rules`:

```bash
alert ssh any any -> any any (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH"; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)
```
<img width="996" height="91" alt="image" src="https://github.com/user-attachments/assets/80f8f656-cb62-4e3d-a7f6-68ede32a6630" />

**This rule detects and alerts when an IP makes 5 or more SSH connection attempts within 60 seconds, indicating a possible brute-force attack.**

#### 3.1.2 Configure Suricata

Edit the Suricata configuration file at /etc/suricata/suricata.yaml. Let’s look for default-rule-path, usually set to /var/lib/suricata/rules. If your custom rule file is in that folder, just use its name (e.g., custom.rules); if it's elsewhere, provide the full path. Since Suricata doesn’t create this file by default, we’ll leave it unchanged for now.

<img width="463" height="134" alt="image" src="https://github.com/user-attachments/assets/7f6a396c-cf71-428b-9771-390de97af586" />


Test config:

Run the following command to check if your Suricata config file is correct:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
<img width="463" height="134" alt="image" src="https://github.com/user-attachments/assets/5e32446d-351a-4d4d-81a1-56abd33ffc1c" />

This verifies that the configuration is valid and there are no syntax errors before starting Suricata.
Now we can start Suricata.

### 3.2 Install Elasticsearch

Use the following command to install Elasticsearch:
```bash
sudo apt install elasticsearch
sudo systemctl start elasticsearch
```

This installs the Elasticsearch service, which will store and index the logs collected from Suricata.

<img width="872" height="289" alt="image" src="https://github.com/user-attachments/assets/1ffa43d4-22c6-46cf-bb09-a9e99024cf3d" />

### 3.4 Install Logstash

Run this command to install Logstash:
```bash
sudo apt install logstash
```

<img width="881" height="203" alt="image" src="https://github.com/user-attachments/assets/b3239899-b83f-4967-80d9-3845979e7c73" />


Logstash will collect, filter, and forward logs (like those from Suricata) to Elasticsearch for indexing

### 3.3 Install Filebeat

```bash
sudo apt install filebeat
```
This installs Filebeat, which will forward Suricata logs to Logstash

Edit `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json

Scroll down and find the output section. Comment out output.elasticsearch: and uncomment and edit output.logstash: like this:

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
Now Filebeat reads Suricata’s JSON logs and sends them to Logstash on port 5044, which processes and forwards them to Elasticsearch.

#### 3.4.1 Logstash Pipeline Configuration

Create `/etc/logstash/conf.d/suricata.conf` and define pipeline.

```bash
{
  "input": {
    "beats": {
      "port": 5044
    }
  },
  "filter": {
    "json": {
      "source": "message",
      "skip_on_invalid_json": true
    },
    "condition": "[event_type] == \"alert\" and [alert][signature] =~ /SSH/",
    "mutate": {
      "add_tag": ["ssh_alert"]
    }
  },
  "output": {
    "elasticsearch": {
      "hosts": ["http://localhost:9200"],
      "index": "suricata-ssh"
    }
  }
}

```

**What It Does:**
Input: Listens for logs from Filebeat on port 5044
Filter: Parses logs as JSON and tags SSH alerts
Output: Sends filtered logs to Elasticsearch and stores them in the suricata-ssh index

Start Logstash:

```bash
sudo systemctl start logstash
```

### 3.5 Install Kibana

Install and start Kibana with the following commands:

```bash
sudo apt install kibana
sudo systemctl start kibana
```
<img width="940" height="236" alt="image" src="https://github.com/user-attachments/assets/aed050fe-76da-4bcf-9425-c3ec08b1cafc" />


Access via: `http://localhost:5601`

This will open Kibana’s dashboard, where you can visualize Suricata logs and alerts.

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
<img width="970" height="250" alt="image" src="https://github.com/user-attachments/assets/58be911d-d59c-492e-a3a2-8b5aa86a9bd3" />


This installs the SSH server, allowing remote login access to your machine and ensures the SSH service starts on boot and runs immediately.

---

### 3.8 Attacks Performed

Now it’s time to simulate an attack on your Ubuntu machine.

**Find Ubuntu IP**
On your Ubuntu system, run: ifconfig

**SSH brute-force attack from Kali Linux using Hydra:**

```bash
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://192.168.137.47
```

<img width="1010" height="273" alt="image" src="https://github.com/user-attachments/assets/109a8e2a-199b-4170-b364-3db587ce4236" />


### 3.9 Detection

Suricata detects repeated SSH login failures and logs them.  
Alerts stored in `/var/log/suricata/eve.json`. Use `grep` to find alerts.

To monitor live logs:

```bash
tail -f /var/log/suricata/eve.json
```
<img width="758" height="385" alt="image" src="https://github.com/user-attachments/assets/c9384430-65b3-479a-bdcc-9ed9399c3a63" />

To search for the specific alert in logs:

```bash
grep -a “SSH Brute Force Attempt” /var/log/suricata/fast.log or eve.json
```

<img width="526" height="292" alt="image" src="https://github.com/user-attachments/assets/33ec2864-2b37-42b8-aeae-4745e489e251" />

This command we use for confirm whether the attack was detected successfully.

### 3.10 Kibana Log Overview

- Use **Discover** to explore logs with filters like `alert.signature: "*Brute*"`  

<img width="970" height="520" alt="image" src="https://github.com/user-attachments/assets/ca2e96e8-1bf1-4358-b1dc-38dad9985e7b" />

The rule worked successfully, and the “SSH Brute Force Attempt” alert is now visible in Kibana logs, confirming detection.

**Brute Force Detection Dashboard**

To visualize brute-force activity in Kibana:

Go to **Kibana → Dashboard → Create New Dashboard**
Add visualizations using Suricata data

- Logs Over Time: Shows the number of Suricata alerts across a timeline. Sudden spikes indicate possible brute-force activity.

<img width="696" height="473" alt="image" src="https://github.com/user-attachments/assets/6ecd3cfd-f0c7-4bd5-88c8-5f5ce3254748" />

- Top Source IPs: Displays IP addresses generating the most alerts, helping identify the main attacker sources.

<img width="673" height="498" alt="image" src="https://github.com/user-attachments/assets/b868c8b6-dca7-4476-bbb7-42fa256218b7" />

---

## 4 Results and Observations

### 4.1 Project Summary

This setup demonstrates how to detect network-based attacks using Suricata IDS integrated with the ELK Stack (Elasticsearch, Logstash, and Kibana) in a virtual lab environment. An Ubuntu machine was used as the target, while Kali Linux simulated attacks.

An SSH brute-force attack was launched using Hydra. Suricata detected the repeated login attempts and generated alerts. The logs were sent to ELK via Filebeat, processed through Logstash, and visualized in Kibana for easy monitoring and analysis.

---
**Thank you for taking the time to read this walkthrough!**
I hope it helped you understand how to set up and visualize network attack detection using Suricata and the ELK Stack. Feel free to leave feedback or share your thoughts!

