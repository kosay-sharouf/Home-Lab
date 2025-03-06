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
![1](https://github.com/user-attachments/assets/231be4b2-109b-4383-b42c-43b8b3e31e08)<br>

### Prerequisites:
- Ubuntu Machine for Shuffle (4GB RAM)
- Ubuntu Machine for Wazuh (4GB RAM)
- Ubuntu Machine for TheHive (4GB RAM)
- Windows 10 for Wazuh Agent (4GB RAM)

## Install And configure Sysmon for deep Windows event logging

Sysmon (System Monitor) is a Windows service and device driver designed to monitor and log system activities. Once installed, it runs continuously, even after system reboots, and records events directly into the Windows event log. It offers comprehensive details on various activities, including process creation, network connections, and modifications to file creation timestamps. <br>

Now Let's start by installing Sysmon from here :<a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"> instal sysmon </a> <br>
We also need to download the Sysmon configuration file from the following URL:<a href="https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml"> Sysmon Modular Configuration. </a> <br>
![2](https://github.com/user-attachments/assets/c3f6d69c-e486-4697-ad40-c6968cce4cfb)<br>

Next, let's extract the Sysmon compressed folder and place the Sysmon configuration file in the same directory as Sysmon.

![3](https://github.com/user-attachments/assets/c1f1d18e-168a-4a80-b8ed-10af432f5b03)<br>

Next, we need to open PowerShell with administratier privileges to configure Sysmon.

`.\Sysmon64.exe -i .\sysmonconfig.xml` <br>
 Now Let's verify whether Sysmon is installed on the system.<br>
 <code> Get-Service Sysmon64 </code><br>
 ![4](https://github.com/user-attachments/assets/2cdcaa98-1226-45f6-a701-d0261baa3b5d)<br>

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


 ![6](https://github.com/user-attachments/assets/7686969c-1644-44d0-890e-a9aa871d86a6)<br>

Finally, we will access the Wazuh dashboard. <br>
![8](https://github.com/user-attachments/assets/07d2c71f-cdf7-4600-a83d-97a63e2cf8aa)<br>

Next, we need to configure Wazuh by setting up a new agent.<br>

![9](https://github.com/user-attachments/assets/f36b40dc-82c0-4df9-b623-6d752978b28c)<br>

We need to put the IP address of the machine where Wazuh is installed.<br>

![10](https://github.com/user-attachments/assets/ead272e4-a091-440e-87f6-5382a6a5f81a)<br>

![11](https://github.com/user-attachments/assets/b9e3cc80-0c20-4a7f-a223-12fb1f5f4752)<br>

Next, execute the following command on the Windows machine where you intend to install the Wazuh agent.<br>
`Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.204.147' WAZUH_AGENT_NAME='faresmorcy' `<br>
Next, we need to initiate the Wazuhsvc service.<br>
`net.exe start WazuhSvc`<br>
![12](https://github.com/user-attachments/assets/3a32c1ca-176c-4eb4-a139-24925b82ba2b)<br>

Next, we need to modify the `ossec.conf` file to configure it for forwarding Sysmon logs to Wazuh.<br>
![13](https://github.com/user-attachments/assets/5c7f45b1-2eed-40c9-808a-41950b0277fe)<br>
I only need to forward the Sysmon logs, nothing else.<br>
Next, restart the Wazuh service.<br>
`Restart-Service WazuhSvc` <br>
Now, let's verify on the Wazuh dashboard whether the Wazuh agent is successfully sending Sysmon events.<br>
![14](https://github.com/user-attachments/assets/3e7f79dc-963b-4b09-8705-a7fd647abba8)<br>

## TheHive for threat detection

TheHive is an open-source Security Incident Response Platform (SIRP) designed to help Security Operations Centers (SOCs), Computer Security Incident Response Teams (CSIRTs), and Computer Emergency Response Teams (CERTs) manage and respond to security incidents efficiently. It provides a collaborative workspace where security teams can analyze, track, and resolve incidents in a streamlined manner.<br>

### Key Features of TheHive:<br>
- #### Case Management:<br>
Create and manage cases with comprehensive details, including tasks, observables, and logs.<br>

- #### Collaboration:<br>
Supports real-time collaboration, allowing multiple users to work on the same case simultaneously for faster resolution.<br>

- #### Integration:<br>
Integrates seamlessly with tools like MISP (Malware Information Sharing Platform) and Cortex to enable automated analysis and data sharing.<br>

- #### Alert Management:<br>
Collects and processes alerts from various sources, facilitating quick triage and prioritization of incidents.<br>

- #### Customizable Dashboards:<br>
Offers user-defined dashboards to visualize incident data and track key performance metrics.<br>

### Scalability and Deployment:<br>
TheHive is designed to scale according to organizational needs. It can be deployed as a standalone node for smaller setups or in a clustered environment for larger, more complex infrastructures.<br>

<a href="https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/#installation">`Installation Guid`</a><br>

Now, let's install TheHive.<br>

First, we need to install the required dependencies.<br>
`apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release` <br>
TheHive requires Java 11, so let's install Amazon Corretto 11 with the following commands:<br>

`wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg`<br>
`echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee /etc/apt/sources.list.d/corretto.list`<br>
`sudo apt update`<br>
`sudo apt install -y java-11-amazon-corretto-jdk`<br>
`echo 'JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"' | sudo tee -a /etc/environment
source /etc/environment`<br>

TheHive uses Apache Cassandra as its database. Let's install it as follows: <br>

`wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg`<br>
`echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee /etc/apt/sources.list.d/cassandra.sources.list`<br>
`sudo apt update`<br>
`sudo apt install -y cassandra`<br>

TheHive requires Elasticsearch for data indexing. Let's install Elasticsearch 7.x with the following commands:<br>
`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg`<br>
`echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elasticsearch-7.x.list`<br>
`sudo apt update`<br>
`sudo apt install -y elasticsearch` <br>

Additionally, let's add TheHive's repository and proceed with the installation.<br>

`wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg`<br>
`echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list`<br>
`sudo apt update`<br>
`sudo apt install -y thehive`<br>

Next, we need to start TheHive and enable it to run on system boot:<br>

`sudo systemctl start thehive`<br>
`sudo systemctl enable thehive`<br>

Now, let's edit Cassandra configuration file:<br>

`nano /etc/cassandra/cassandra.yaml`<br>

Enter the IP address of the machine where TheHive is installed.<br>
![15](https://github.com/user-attachments/assets/effbdb3e-0355-4bec-b03a-ea6a64f98987)<br>

![16](https://github.com/user-attachments/assets/8543d74f-e5c4-483f-8489-11eef093318f)<br>

![17](https://github.com/user-attachments/assets/1e3cf1d0-9b9a-481f-a40e-8f8a2b441f1d)<br>


After installation, let's start and enable Cassandra:<br>

`sudo systemctl start cassandra`<br>
`sudo systemctl enable cassandra`<br>
We also need to edit the configuration for Elasticsearch.<br>

`nano /etc/elasticsearch/elasticsearch.yml`<br>
![18](https://github.com/user-attachments/assets/91ba0ef3-1c4b-4906-b2b9-ba15f0cee30d)<br>
![19](https://github.com/user-attachments/assets/0bab5a90-e3c2-473f-83a8-f8a70c01833f)<br>

Next, let's start and enable Elasticsearch:<br>

`sudo systemctl start elasticsearch`<br>
`sudo systemctl enable elasticsearch`<br>
Next, we need to modify TheHive's configuration. However, before proceeding, we must update the ownership of the `/opt/thp` directory, assigning it to the `thehive` user and group.<br>

`chown -R thehive:thehive /opt/thp`<br>
![20](https://github.com/user-attachments/assets/bd563a2e-c124-463e-a7fd-ee4a3509d75a)<br>

`nano /etc/thehive/application.conf`<br>
![21](https://github.com/user-attachments/assets/6dbd9ab9-edfc-4cdb-b8d3-4440832b00b4)<br>

![22](https://github.com/user-attachments/assets/10518305-7a6f-433a-9e27-7843cf6573b9)<br>

Now, let's access TheHive by navigating to `http://192.168.204.149:9000`.<br>
![23](https://github.com/user-attachments/assets/e91cba42-f594-43f7-bc50-3593d545fb99)<br>

The default admin user credentials are as follows:<br>
- Username: admin@thehive.local <br>
- Password: secret <br>

I encountered an authentication failure when attempting to access it. Let's work on resolving this issue.<br>

`nano /etc/elasticsearch/jvm.options.d/jvm.option`<br>

`-Dlog4j2.formatMsgNoLookups=true
-Xms2g<br>
-Xmx2g`<br>
![24](https://github.com/user-attachments/assets/f679fc14-8b76-4dbe-92a6-d0325923ab33)<br>

Then restart the Elasticsearch.<br>


`systemctl restart elasticsearch`<br>
Now, let's access TheHive again.<br>
![25](https://github.com/user-attachments/assets/790aea2b-50c5-428a-ad27-66ccaeb6b842) <br>

## Execute Mimikatz and create detection rules in Wazuh <br>

First, let's open Virus & Threat Protection to add the Downloads folder as an exclusion. <br>
![26](https://github.com/user-attachments/assets/2fbe2f27-a0f2-4c4d-a323-1e3c44db58ee)<br>

![27](https://github.com/user-attachments/assets/b9bfc656-6a7b-4330-b4ef-0e34475b3f38)<br>

![28](https://github.com/user-attachments/assets/03cb980d-caa3-4811-8b92-70a13a12e96c)<br>
![29](https://github.com/user-attachments/assets/ed265da8-4ca2-4c03-98f1-f8b849ecfcfb)<br>

Now, let's install Mimikatz from this <a href="https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe">`link`<a><br>
![30](https://github.com/user-attachments/assets/d5f3892b-6c28-4489-9c18-6ad32e48aa9d)<br>

Now, let's execute mimikatz.exe and review the Wazuh dashboard for any related detections or alerts.<br>

`.\mimikatz.exe Add-MpPreference -ExclusionProcess "mimikatz.exe"`<br>
![31](https://github.com/user-attachments/assets/810ca81d-401d-4392-bc2b-4f788a8d0a5c)

When I execute `mimikatz.exe`, Windows Defender blocks it. To proceed, I need to exclude the `mimikatz` process from detection.<br>

Now, let's check the Wazuh dashboard for any related detections or alerts.<br>
![32](https://github.com/user-attachments/assets/b9449165-aa22-43ec-8f6b-c59938d34481)

Upon reviewing Wazuh, I did not find any indicators related to Mimikatz.<br>

By default, Wazuh does not log all events; it only generates logs when a rule is triggered or an alert is generated. However, this behavior can be modified by configuring the `ossec.conf` file within the Wazuh Manager to enable comprehensive logging. Alternatively, specific rules can be created to monitor particular events. When these events occur, they will trigger an alert in Wazuh, allowing for efficient searching and analysis.<br>

Next, let's proceed with editing the `ossec.conf` file.<br>
`nano /var/ossec/etc/ossec.conf`<br>
![33](https://github.com/user-attachments/assets/cce45b93-148b-4c9d-8509-e2a9d7cafc64)

Now, let's restart the Wazuh manager.<br>

`systemctl restart wazuh-manager` <br>
This action compels Wazuh to start archiving all logs and store them in a file named "archives."<br>

`cd /var/ossec/logs/archives/`<br>
`ls`<br>
![34](https://github.com/user-attachments/assets/0e0d3c4f-c667-4d84-a8b3-9efa77927fcf) <br>

We also need to configure the `filebeat.yml` file.<br>

![35](https://github.com/user-attachments/assets/3ca74ee1-4699-4e66-8286-a7782789badf)

Next, let's restart the Filebeat manager.<br>

`systemctl restart filebeat` <br>
Next, we need to create an index for the archives. Let's move forward with this step.<br>
![36](https://github.com/user-attachments/assets/fbbcd682-29e1-46e7-95d3-39b503ea5fcf)<br>
![37](https://github.com/user-attachments/assets/0d9a2db0-2ffa-490a-aec8-247049534a31)<br>
![38](https://github.com/user-attachments/assets/4837bba3-89ae-48fa-b94a-4206d14c4d45)<br>
![39](https://github.com/user-attachments/assets/e1a17782-56f4-4784-a818-f3c0cad75c88)<br>
![40](https://github.com/user-attachments/assets/281ad190-64ca-49e6-9a8e-2ba0c8e5c6df)<br>




