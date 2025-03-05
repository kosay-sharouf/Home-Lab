# Build Home Lab - SOC Automation

## Objective


The Home Lab Project is a mini virtual environment that simulates the work environment of the Security Operations Center and is helpful to understand the work in cybersecurity. We enable attack simulations such as malware attacks, phishing emails, exploiting vulnerabilities, incident response, and log analysis.

### Skills Learned

- Install And configure Sysmon for deep Windows event logging.
- Ability to Set up Wazuh .
- Automate everything with Shuffle.
- TheHive for threat detection .
- Execute Mimikatz & create detection rules in Wazuh.
- Response to SSH Attack Using Shuffle, Wazuh, and TheHive

### Tools Used


- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Sysmon for deep Windows event logging.
- Wazuh And TheHive for threat detection And case management.
- set up Shuffle and Configure

## Steps
Lab Scenario:
![1](https://github.com/user-attachments/assets/231be4b2-109b-4383-b42c-43b8b3e31e08)

### Prerequisites:
- Ubuntu Machine for Shuffle (4GB RAM)
- Ubuntu Machine for Wazuh (4GB RAM)
- Ubuntu Machine for TheHive (4GB RAM)
- Windows 10 for Wazuh Agent (4GB RAM)

## Install And configure Sysmon for deep Windows event logging

Sysmon (System Monitor) is a Windows service and device driver designed to monitor and log system activities. Once installed, it runs continuously, even after system reboots, and records events directly into the Windows event log. It offers comprehensive details on various activities, including process creation, network connections, and modifications to file creation timestamps.

Now Let's start by installing Sysmon from here :<a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"> instal sysmon </a>
We also need to download the Sysmon configuration file from the following URL:<a href="https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml"> Sysmon Modular Configuration. </a>
![2](https://github.com/user-attachments/assets/c3f6d69c-e486-4697-ad40-c6968cce4cfb)

Next, let's extract the Sysmon compressed folder and place the Sysmon configuration file in the same directory as Sysmon.

![3](https://github.com/user-attachments/assets/c1f1d18e-168a-4a80-b8ed-10af432f5b03)

Next, we need to open PowerShell with administratier privileges to configure Sysmon.

`.\Sysmon64.exe -i .\sysmonconfig.xml`
 Now Let's verify whether Sysmon is installed on the system.
 <code> Get-Service Sysmon64 </code>
 ![4](https://github.com/user-attachments/assets/2cdcaa98-1226-45f6-a701-d0261baa3b5d)

 We can also verify this using the Event Viewer.
 Applications and Services Logs -> Microsoft -> Windows -> Sysmon
 ![5](https://github.com/user-attachments/assets/2cf1a112-d6b2-4cec-97b1-cea292d3b311)

 That is Creat , Now Lets go to the section Tow
 




