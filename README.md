# Build Home Lab - SOC Automation

## Objective


The Home Lab Project is a mini virtual environment that simulates the work environment of the Security Operations Center (SOC) and is helpful to understand the work in cybersecurity. We enable attack simulations such as malware attacks, phishing emails, exploiting vulnerabilities, incident response, and log analysis.

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

Sysmon (System Monitor) is a Windows service and device driver designed to monitor and log system activities. Once installed, it runs continuously, even after system reboots, and records events directly into the Windows event log. It offers comprehensive details on various activities, including process creation, network connections, and modifications to file creation timestamps. <br>

Now Let's start by installing Sysmon from here :<a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"> instal sysmon </a> <br>
We also need to download the Sysmon configuration file from the following URL:<a href="https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml"> Sysmon Modular Configuration. </a> <br>
![2](https://github.com/user-attachments/assets/c3f6d69c-e486-4697-ad40-c6968cce4cfb)

Next, let's extract the Sysmon compressed folder and place the Sysmon configuration file in the same directory as Sysmon.

![3](https://github.com/user-attachments/assets/c1f1d18e-168a-4a80-b8ed-10af432f5b03)

Next, we need to open PowerShell with administratier privileges to configure Sysmon.

`.\Sysmon64.exe -i .\sysmonconfig.xml` <br>
 Now Let's verify whether Sysmon is installed on the system.<br>
 <code> Get-Service Sysmon64 </code><br>
 ![4](https://github.com/user-attachments/assets/2cdcaa98-1226-45f6-a701-d0261baa3b5d)

 We can also verify this using the Event Viewer.<br>
 `Applications and Services Logs -> Microsoft -> Windows -> Sysmon`<br>
 ![5](https://github.com/user-attachments/assets/2cf1a112-d6b2-4cec-97b1-cea292d3b311)<br>

 That is Creat, Now Lets go to the section Tow <br>

 ## Set Up Wazuh
 
 Wazuh is a free, open-source security platform that combines Extended Detection and Response (XDR) and Security Information and Event Management (SIEM) functionalities. It delivers robust protection for endpoints and cloud workloads, empowering organizations to detect, analyze, and respond to threats efficiently. <br>

### Key Features of Wazuh:<br>
- #### Intrusion Detection:<br>
Continuously monitors systems to detect unauthorized access or malicious activities.<br>

- #### Log Data Analysis:<br>
Collects and analyzes logs from multiple sources to identify potential security incidents.<br>

- #### File Integrity Monitoring:<br>
Tracks changes to critical files and directories, notifying administrators of unauthorized modifications.<br>

- #### Vulnerability Detection:<br>
Identifies known vulnerabilities in both software and hardware components across the network.<br>

- #### Configuration Assessment:<br>
Evaluates system configurations to ensure adherence to security policies and standards.<br>

- #### Incident Response:<br>
Provides tools and capabilities to quickly respond to and mitigate security incidents.<br>

- #### Regulatory Compliance:<br>
Helps organizations meet compliance requirements by offering essential security controls and reporting tools.<br>

- #### Cloud Security:<br>
Monitors and secures cloud-based infrastructures, ensuring protection across diverse environments.<br>

### Wazuh Architecture:<br>
Wazuh operates using lightweight agents installed on monitored systems and a centralized management server. The server processes and analyzes data collected by the agents, enabling comprehensive security monitoring and threat detection.<br>

Let's start by installing Wazzuh:<br>
`curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh && sudo bash ./wazuh-install.sh -a` <br>


 ![6](https://github.com/user-attachments/assets/7686969c-1644-44d0-890e-a9aa871d86a6)

Finally, we will access the Wazuh dashboard. <br>
![8](https://github.com/user-attachments/assets/07d2c71f-cdf7-4600-a83d-97a63e2cf8aa)

Next, we need to configure Wazuh by setting up a new agent.<br>

![9](https://github.com/user-attachments/assets/f36b40dc-82c0-4df9-b623-6d752978b28c)

We need to put the IP address of the machine where Wazuh is installed.<br>

![10](https://github.com/user-attachments/assets/ead272e4-a091-440e-87f6-5382a6a5f81a)

![11](https://github.com/user-attachments/assets/b9e3cc80-0c20-4a7f-a223-12fb1f5f4752)

Next, execute the following command on the Windows machine where you intend to install the Wazuh agent.<br>
`Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.204.147' WAZUH_AGENT_NAME='faresmorcy' `<br>
Next, we need to initiate the Wazuhsvc service.<br>
`net.exe start WazuhSvc`<br>
![12](https://github.com/user-attachments/assets/3a32c1ca-176c-4eb4-a139-24925b82ba2b)

Next, we need to modify the `ossec.conf` file to configure it for forwarding Sysmon logs to Wazuh.<br>
![13](https://github.com/user-attachments/assets/5c7f45b1-2eed-40c9-808a-41950b0277fe)
I only need to forward the Sysmon logs, nothing else.<br>
Next, restart the Wazuh service.<br>
`Restart-Service WazuhSvc` <br>
Now, let's verify on the Wazuh dashboard whether the Wazuh agent is successfully sending Sysmon events.<br>
![14](https://github.com/user-attachments/assets/3e7f79dc-963b-4b09-8705-a7fd647abba8)



