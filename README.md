# wazuh-soc-lab

## What is Wazuh?

Wazuh is a open source security platform that combines XDR and SIEM capabilities. It protects workloads across cloud, container, and on-premises (local) environments. Basically, it’s a centralized logging platform.

### **Main Components**:

Wazuh uses an architecture split into one single agent and three central components:

- **Wazuh Agent (Collect)**: Runs on endpoints (Linux, Windows, macOS) to collect system data and logs.
- **Wazuh Server (Analyzes)**: takes everything that the agent send, runs it through decoders and rules, and uses threat intelligence to look for known indicators of compromise (IOCs). The server also manages the agents, so that we can configure and upgrade them remotely.
- **Wazuh Indexer (Stores)**: is the search and analytics engine. It indexes and stores the alerts the server generates.
- **Wazuh Dashboard (Visual)**: provides a web interface for data visualization, threat hunting and compliance. There is also where we manage the configuration and check if everything is ok.

### **Key Features**:

- File Integrity Monitoring (FIM): monitors directories and files that we tell it to watch and will alert us when something is created, modified or deleted.
- Active response: is an automated action. When a rule of a certain severity fires, Wazuh is going to run a script. For example, blocking the source IP of an SSH brute force account, blocking a know malicious IP address based on reputation data.
