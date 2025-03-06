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

Let's return to the Discover page.<br>
![41](https://github.com/user-attachments/assets/12e505bd-93ea-4c29-ac47-3cde0af4c202)<br>
Let's execute Mimikatz again and review the logs in the Wazuh dashboard.<br>
![42](https://github.com/user-attachments/assets/92b164f0-e8a0-44fc-b3b6-3f33b9237e78)<br>
![43](https://github.com/user-attachments/assets/27e0ab2e-97f7-4c03-a894-1197d1eb9dfe)<br>

We now need to create a rule to detect and generate an alert for Mimikatz activity.<br>
![44](https://github.com/user-attachments/assets/3c48d69c-4289-4a83-852c-040388ed3b52)<br>
![45](https://github.com/user-attachments/assets/d7072161-eefb-4b34-9842-a004b0c0e895)<br>
![46](https://github.com/user-attachments/assets/d0abca09-cfe2-4a47-b24c-e86118521574)<br>

We need to copy this section as it will be used to create a custom rule.<br>
![47](https://github.com/user-attachments/assets/579ee837-04c9-42f2-9715-48675eb23185)<br>
Let's proceed with creating our custom rule.<br>
![48](https://github.com/user-attachments/assets/ec8aeeff-0948-4a9c-8906-bf86f557ccd0)<br>
![49](https://github.com/user-attachments/assets/15bdaba5-3b50-4c57-aa8c-6262f6d68d29)<br>
![50](https://github.com/user-attachments/assets/b3f5cb4f-76cd-42ae-8938-86073da42009)<br>
<pre>
 <rule id="100002" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>   
</pre> <br>
  
  ![51](https://github.com/user-attachments/assets/bc8a4ba5-0ef9-499f-b111-077f0b6434a0)<br>

  The `win.eventdata.originalFileName` field refers to the original name embedded within the file's metadata, which doesn't change even if the file is renamed on disk. Therefore, if an attacker simply renames `mimikatz.exe` to another name, this rule would still trigger an alert because the original filename remains `mimikatz.exe`.<br>

Let's rename `mimikatz.exe` to an alternative name, execute it, and verify whether Wazuh generates an alert.<br>

![52](https://github.com/user-attachments/assets/3ccab3a9-3da2-41f5-a3e3-be8ab2c1a5f6)<br>
![53](https://github.com/user-attachments/assets/72bd6cd8-e3e6-4a09-80df-50990c559de5)<br>
![54](https://github.com/user-attachments/assets/de71baa0-d08a-4ff8-9dce-9200c51ef5ef)<br>
![55](https://github.com/user-attachments/assets/915d2337-12d5-45f2-9774-cd37239e1e04)<br>
![56](https://github.com/user-attachments/assets/64f1676c-ee8a-4e71-814a-7971d3caa7b6)<br>

If the rule is based on the image, the alert will not be triggered.<br>


## Automate everything with Shuffle <br>
Let's begin by installing Shuffle on Ubuntu.<br>
`sudo apt update && sudo apt install -y docker.io docker-compose`<br>
`sudo systemctl enable docker`<br>
`sudo systemctl start docker`<br>
`git clone https://github.com/Shuffle/Shuffle.git`<br>
`cd Shuffle`<br>
`sudo docker-compose up -d`<br>

After the installation is complete, access the application by navigating to http://your-ip:3001 in your web browser.<br>
![57](https://github.com/user-attachments/assets/815e5a75-ff1e-4fde-8bec-2b4447220289)<br>
After executing these commands, we will proceed to create an account and log in.<br>

`sudo chown -R 1000:1000 shuffle-database`<br>
`sudo swapoff -a`<br>
`sudo docker restart shuffle-opensearch`<br>
![58](https://github.com/user-attachments/assets/3133a2f1-b5be-4153-bdb9-f9becfb327d5)<br>
![59](https://github.com/user-attachments/assets/e084c6da-a7db-403a-a3ad-72672eaa207e)<br>
After creating the workflow, you may notice that several applications are missing. To address this, we need to take the following steps.<br>
![60](https://github.com/user-attachments/assets/3a644af3-f198-4368-a126-5e2ad5027659)
![61](https://github.com/user-attachments/assets/78aadda3-4d68-4107-867f-f54e7e24282a)

Now, let's proceed with creating a new workflow.<br>
![62](https://github.com/user-attachments/assets/da39e3b2-e939-4680-b146-d4913ccf88e9)

Next, we need to set up a webhook to receive alerts from the Wazuh dashboard.<br>
![63](https://github.com/user-attachments/assets/baf34abe-b45b-4528-95c0-6aedb0c9ab6f)
![64](https://github.com/user-attachments/assets/76e2a0a2-27a7-45e1-a59c-602d6b607978)
On the Wazuh server, open the `/var/ossec/etc/ossec.conf` file. Insert the webhook URL within the `<hook_url>` tags.<br>
`sudo nano /var/ossec/etc/ossec.conf`<br>
<pre>
   <integration>
    <name>shuffle</name>
    <hook_url>http://192.168.204.151:3001/api/v1/hooks/webhook_82a81730-b6b5-476f-8eab-225c6b165fda </hook_url>
    <rule_id>100002</rule_id>
    <alert_format>json</alert_format>
  </integration>
</pre> <br>
![65](https://github.com/user-attachments/assets/e0cba06b-4e52-4afe-a1f4-824d926488b5)

Here, I aim to receive alerts for Rule ID 100002, which we previously configured for Mimikatz detection. You can modify the rule to capture additional alerts based on your requirements or adjust the alert level as needed.<br>

After saving the changes, let's restart the Wazuh manager to apply the new configuration:​<br>

`systemctl restart wazuh-manager` <br>
Next, let's run Mimikatz again to verify whether the alert generated by Wazuh is successfully sent to Shuffle.<br>
![66](https://github.com/user-attachments/assets/271a8cce-571e-4be1-b3af-48824f21cb09)<br>
![67](https://github.com/user-attachments/assets/51d767e5-4ea5-4639-b6a6-d85b7c1ba5b2)<br>
Now, let's verify whether any alerts have been triggered in the Shuffle workflow.<br>
![68](https://github.com/user-attachments/assets/6f5a8a78-092f-4ff7-a49d-24efd2b67d2d)
![69](https://github.com/user-attachments/assets/e2601a55-e9e9-45a6-a451-17bafa95da41)
![70](https://github.com/user-attachments/assets/7a4bf117-2798-494d-8400-2c36788d993e)

### Workflow:<br>
- Mimikatz Alert Trigger – A Mimikatz alert is generated and sent to Shuffle.<br>

- Alert Processing in Shuffle – Shuffle receives the alert and extracts the SHA-256 hash of the detected file.<br>

- Reputation Check – The extracted hash is queried against VirusTotal to assess its reputation score.<br>

- Alert Creation in TheHive – The analysis details are forwarded to TheHive to generate an incident alert.<br>

- Notification to SOC Analyst – A notification is sent to the SOC Analyst through telegram bot, prompting them to initiate an investigation.<br>

Next, we need to obtain the file's hash to verify it on VirusTotal. To do this, let's follow these steps.<br>
![71](https://github.com/user-attachments/assets/959d1355-dc90-419d-8c23-3d0f3b5c99a3)<br>
![72](https://github.com/user-attachments/assets/308b406c-77c4-482e-ab72-1eff7201b70c)<br>
Hover over the Execution Argument.<br>
![73](https://github.com/user-attachments/assets/dd0bc1ee-c181-49ac-a6b4-c58e726f3a9b)<br>
Next, we need to create a regular expression specifically designed to extract only the SHA-256 hash.<br>
![74](https://github.com/user-attachments/assets/4341412a-8a94-4353-8cd6-c4c8c3b21d2b)<br>
![75](https://github.com/user-attachments/assets/851268d0-095b-4dc1-aa49-f0ec8b6b05c7)<br>
![76](https://github.com/user-attachments/assets/eb262dc6-13b4-473e-884c-687e41bd8458)<br>
Let's rename it from Wazuh_Receive_alerts to SHA256.<br>
We now need to submit this SHA-256 hash to VirusTotal for analysis.<br>
![77](https://github.com/user-attachments/assets/fd12d0a9-a488-4ddd-ab2f-8086690e00f5)<br>
Please retrieve your API key from your VirusTotal account and enter it here.<br>
![78](https://github.com/user-attachments/assets/105e92fa-c6aa-4b68-b34e-052b81720008)<br>
![79](https://github.com/user-attachments/assets/286d6e68-8a14-46ad-8afd-fba9f3a77a00)<br>
![80](https://github.com/user-attachments/assets/bce83f05-c5e4-4bbe-bdb1-93c7188f55b4)<br>
Let's run it again.<br>
![81](https://github.com/user-attachments/assets/e75d3c2c-aa9a-4cdf-b9fe-7e28044e273c)<br>
![82](https://github.com/user-attachments/assets/3f662505-1885-452f-a2fc-916ec06af56c)<br>
![83](https://github.com/user-attachments/assets/89748902-c393-401e-94b4-36488cd858c8)<br>
![84](https://github.com/user-attachments/assets/32ae8342-7b45-424f-beb4-cacd57763739)<br>
Let's check the attributes. <br>
![85](https://github.com/user-attachments/assets/b4373de3-49bc-4179-8ebb-615a08e193d9)<br>
This means that 65 security scanners have identified the file as malicious.<br>

Next, we need to forward the results provided by VirusTotal to TheHive.<br>

![86](https://github.com/user-attachments/assets/0de0c870-6776-48a2-90b8-7234fa6e7b57)<br>
Let's transition to TheHive and proceed with creating a new organization along with user accounts for it.<br>
![87](https://github.com/user-attachments/assets/7cbb73f7-38e8-40c5-a8bc-626dfb5da75c)<br>
![88](https://github.com/user-attachments/assets/71de2c93-9580-493e-9600-093fa990d179)<br>
Now, let's create new users. <br>
![89](https://github.com/user-attachments/assets/6858a60c-4df5-4806-af7b-8e8f15ef56ab)<br>
![90](https://github.com/user-attachments/assets/0c24a2ff-21ca-4e68-b53d-9279113a3aec)<br>
![91](https://github.com/user-attachments/assets/6b30f9b9-e541-4ff8-a185-2a8f15609d75)<br>
![92](https://github.com/user-attachments/assets/3a93091a-a1cf-48c9-b23e-b7f9284f8a2d)<br>

Now, we need to set a password for Omar's account and generate an API key for the SOAR account.<br>
![93](https://github.com/user-attachments/assets/553adb39-c957-4a63-a11e-d54e0cc8bb1d)<br>
![94](https://github.com/user-attachments/assets/2064318e-459a-4cf5-821b-f50b5d3aeba5)<br>
![95](https://github.com/user-attachments/assets/fd9f8d82-e99a-4110-9c2e-1618a65566af)<br>
Now, we will use this API key to establish a connection with Shuffle.<br>
![96](https://github.com/user-attachments/assets/6638a05a-a2df-4fcb-aada-79eae05c11f0)<br>
![97](https://github.com/user-attachments/assets/a3b11ca7-3205-47da-9fa7-3b12daae1c8b)<br>
![98](https://github.com/user-attachments/assets/d461f73d-ba6b-4747-9e57-07f7de717695)<br>
Certain fields need to be completed.<br>
`Summary -> Mimikatz Activity Detected on host: $exec.text.win.system.computer and the Process Id: $exec.text.win.eventdata.processId and the Commandline: $exec.text.win.eventdata.commandLine
Description -> Mimikatz Detected on host:$exec.text.win.system.computer`<br>
Let's execute the workflow again.<br>
![99](https://github.com/user-attachments/assets/cfb5d594-b2ab-440e-8632-32165435ad2f)<br>
![100](https://github.com/user-attachments/assets/46f371c4-b137-49fd-a81b-d124399787ed)<br>

Next, we need to rerun the process to ensure everything functions correctly.<br>
![101](https://github.com/user-attachments/assets/2bf89ee7-9240-4a47-a611-9523cacbac6a)<br>
Now, let's log in to TheHive using the previously created account, "Kosay," to check for any alerts.<br>
![102](https://github.com/user-attachments/assets/bc30b13e-0365-4cc7-8e1b-73f0f7efa7a9)<br>
![103](https://github.com/user-attachments/assets/60eaf3c0-38d4-4eea-86ef-a687b7cfc834)<br>


## Response to SSH Attack Using Shuffle, Wazuh, and TheHive
Let's explore a different scenario:

- Create ubuntu machine

- Install Wazuh agent on ubuntu

- Perform SSH attack on this machine

- Push all level 5 alerts to Shuffle

- Perform IP enrichment using VirusTotal

- Send details to the analyst via telegrm bot (ask to block source ip)

- Create an alert in TheHive

  Let's start by setting up a new Ubuntu machine and conduct an SSH attack on it. However, before proceeding with the attack, we need to install a Wazuh agent on the machine to collect and analyze logs for monitoring and security analysis.<br>
  
![image](https://github.com/user-attachments/assets/a1d6dd43-1e02-425d-a9be-e160b8fe2559)<br>
![image](https://github.com/user-attachments/assets/702a27e2-4529-4867-93de-f404bf45740e)<br>
![image](https://github.com/user-attachments/assets/39fa74bf-7752-463d-bce4-a8e5f6240e5b)<br>

Let's run this command on the Ubuntu machine we set up to install the Wazuh agent.<br>
`wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.10.1-1_amd64.deb && sudo WAZUH_MANAGER='192.168.204.150' WAZUH_AGENT_NAME='Ubuntu' dpkg -i ./wazuh-agent_4.10.1-1_amd64.deb`<br>
![image](https://github.com/user-attachments/assets/8ff27c26-9195-4a58-a1f7-becbf82243f0)<br>
`sudo systemctl daemon-reload`<br>
`sudo systemctl enable wazuh-agent`<br>
`sudo systemctl start wazuh-agent`<br>
`sudo systemctl status wazuh-agent`<br>
![image](https://github.com/user-attachments/assets/4d8c4a76-ee96-4b9d-9220-d2f174d8e91c)<br>

Let's install the SSH server on the Ubuntu machine that will be used as the target for the SSH attack.<br>
`sudo apt update`<br>
`sudo apt install openssh-server -y`<br>
`sudo systemctl start ssh`<br>
`sudo systemctl enable ssh`<br>
`sudo systemctl status ssh`<br>
![image](https://github.com/user-attachments/assets/b5b65ebf-8576-4b2d-9c54-4819ef99a23b)<br>
Next, we need to conduct an SSH attack on this machine from a separate system. I created two files containing usernames and passwords to utilize in the attack.<br>
`hydra -L users.txt -P passwords.txt ssh://192.168.204.146`<br>
![image](https://github.com/user-attachments/assets/90b93ad7-9062-400f-b44d-e0cece25eb3b)<br><br><br>
Let's review the logs to determine the cause of the attack.<br>
![image](https://github.com/user-attachments/assets/09839b08-4fdc-41b6-887c-9ecfd6db5a66)<br><br><br>

Let's review our Wazuh dashboard to determine if any logs related to this attack have been recorded.<br>
![image](https://github.com/user-attachments/assets/cbfebfeb-c8ad-44b1-932c-37b7f81f643c)<br><br>
![image](https://github.com/user-attachments/assets/09072659-83d1-4c39-a59e-94f0756c2b19)<br><br>
![image](https://github.com/user-attachments/assets/1e252ebe-aa99-4ad0-a9e4-8faa28ef78cc)<br><br>
![image](https://github.com/user-attachments/assets/0f0a41de-bb39-4649-a45b-149ed4986e81)<br><br>

We are currently observing a significant number of Level 5 alerts related to SSH brute-force attacks. To enhance detection, we will create a rule that triggers an additional alert when the specific Level 5 alert "sshd: Attempt to login using a non-existent user" occurs more than three times within a 60-second timeframe. This new alert will explicitly indicate that an SSH brute-force attack is in progress.<br><br>

`nano /var/ossec/etc/rules/local_rules.xml`<br>
<pre>
  <rule id="5764" level="10" frequency="3" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Multiple SSH login attempts using non-existent usernames.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</pre> <br><br>
![image](https://github.com/user-attachments/assets/ed13bcdc-6828-4831-af85-8d91319a4959)<br><br>

`systemctl restart wazuh-manager`<br>

### Rule Breakdown:
1- `<rule id="5764" level="10" frequency="3" timeframe="60">`:<br>
- `id="5764"`: A unique identifier for this rule.

- `level="10"`: The severity level of the alert (10 is relatively high, indicating a significant security event).

- `frequency="3"`: The rule triggers an alert if the event occurs 3 times.

- `timeframe="60"`: The event must occur 3 times within 60 seconds for the alert to trigger.

2- `<if_matched_sid>5710</if_matched_sid>`:

- This rule depends on another rule with ID `5710`. Rule `5710` is typically a base rule that detects a single failed SSH login attempt using a non-existent username.

- This means the rule will only trigger if rule `5710` has already matched (i.e., a failed SSH login attempt with an invalid username has been detected).

3- `<same_source_ip />`:

- This ensures that the same source IP address is responsible for the multiple failed attempts.

- Without this, the rule might trigger for failed attempts from different IPs, which is less indicative of a brute-force attack.

4- `<description>Multiple SSH login attempts using non-existent usernames.</description>`:

- A human-readable description of the rule. This will appear in the alert message.

5- `<mitre><id>T1110</id></mitre>`:

- Maps this rule to the MITRE ATT&CK framework.

- `T1110` refers to the technique "Brute Force", which is used by attackers to guess usernames and passwords.

Let's simulate the brute force attack again to verify the effectiveness of the rule.<br><br>
`hydra -L users.txt -P passwords.txt ssh://192.168.204.146`<br>
![image](https://github.com/user-attachments/assets/955a194a-cd1a-494f-bc7d-6689149f7e21)<br><br>

Next, let's review the alerts in the Wazuh dashboard.<br>
![image](https://github.com/user-attachments/assets/1bc03735-b2b3-47a8-b6c5-6beddee39263)<br><br>
We received an alert triggered by Rule ID 5764, which we previously configured to activate when Event ID 5710 occurs three times. To reduce the frequency of alerts, we can modify the rule to trigger after five occurrences instead of three.<br><br>
![image](https://github.com/user-attachments/assets/23a7ae2f-0fab-4c56-b932-c289b75a0968)<br><br>
Next, let's set up a webhook to receive alerts from the Wazuh dashboard.<br><br>
![image](https://github.com/user-attachments/assets/d39575cc-6c45-427f-b295-4e15bf101ed5)<br><br>
![image](https://github.com/user-attachments/assets/4b563033-998d-49d1-a3bc-569ebe0a31f4)<br><br>
Now, let's modify the Wazuh configuration to include our webhook URL.<br><br>
`nano /var/ossec/etc/ossec.conf`<br><br>
![image](https://github.com/user-attachments/assets/7d6022e2-e88a-479f-92b1-d35c0b6d07fb)<br><br>
`systemctl restart wazuh-manager`<br>
Let's reattempt the attack and check if any results appear in Shuffle.<br><br>
![image](https://github.com/user-attachments/assets/72c9c210-ea30-4819-a818-ebb1e768393b)<br><br>
We now need to submit the IP address to VirusTotal for analysis.<br><br>
![image](https://github.com/user-attachments/assets/e8b5b621-8c23-42be-b52b-02098dcff190)<br><br>
As previously mentioned, you must provide your API key for authentication.<br><br>
![image](https://github.com/user-attachments/assets/2921b996-56e8-463c-9cc8-561d48d0ea23)<br><br>
Let's rerun the process and review the results from VirusTotal.<br><br>
![image](https://github.com/user-attachments/assets/74c237c5-8ee9-4a51-9d6c-aaf60a1bab80)<br><br>
![image](https://github.com/user-attachments/assets/e9ca5647-7a97-440b-8826-4682d74ab6b7)<br><br>
Since this is our internal IP address, it is not classified as malicious by VirusTotal.<br><br>
![image](https://github.com/user-attachments/assets/d75e56ad-9fb7-42ce-a1cf-6de6030b97e0)<br><br>
Before proceeding with obtaining the Wazuh API to block the IP address involved in SSH brute-force attacks on an Ubuntu machine, it is essential to first understand Wazuh's Active Response mechanism.<br><br>

​Wazuh's Active Response feature enables automated reactions to detected threats by executing predefined scripts or commands. A common application is blocking malicious IP addresses to safeguard your systems. <br><br>

Active Response is a Wazuh feature that enables automated actions (e.g., blocking an IP, killing a process) in response to detected threats. For example:<br><br>

- Block an IP address after multiple failed SSH login attempts.

- Block an IP address after a port scan is detected.

Let's open the Wazuh manager configuration file:<br><br>
`nano /var/ossec/etc/ossec.conf`<br><br>
![image](https://github.com/user-attachments/assets/3032960d-273f-4de8-a269-32b69fc3e48b)<br><br>
We need to specify the action to be taken when a threat is detected. Wazuh provides default scripts, like `firewall-drop`, which utilize the system's firewall to block IPs.​<br><br>
![image](https://github.com/user-attachments/assets/3787ad3a-4a05-4add-92b5-986dcade6276)<br><br>
<pre>
 <command>firewall-drop</command>
<location>local</location>
<rules_id>5764</rules_id>                                          
<timeout>no</timeout>
</pre> <br><br>

- `firewall-drop`: This is the command that will execute the script to block the IP.

- `rules_id`: Specify the rule IDs that should trigger the Active Response.

- `local`: Indicates that the command should run on the agent where the threat was detected.

- `no`: Specifies that the block remains indefinitely, requiring manual intervention to lift it.

This setup ensures that when rule 5764 is triggered, the offending IP is blocked locally without an automatic unblock.<br><br>​

Next, let's save the file and restart the Wazuh Manager to apply the changes.<br><br>

`systemctl restart wazuh-manager`<br><br>
Before proceeding with using Shuffle to block the IP, let's first understand the scenario. There is a tool called agent_control. This tool, provided by Wazuh, enables administrators to manage and monitor Wazuh agents from the Wazuh Manager. It allows for various administrative tasks, including listing connected agents, restarting or removing agents, and checking their status.<br><br>

Also, Wazuh's `agent_control` utility can be used to manually block specific IP addresses across your monitored endpoints.<br><br>
![image](https://github.com/user-attachments/assets/9fc268a1-426e-46dd-aa39-b25dab905447)<br><br>
Let's display the list of available active responses.<br><br>
`./agent_control -L`<br><br>
![image](https://github.com/user-attachments/assets/33b3a1d0-d634-4690-997d-350faf001195)<br><br>
Here is the active response we created before. This command will display all configured active responses, allowing us to choose the appropriate one for blocking IP addresses. ​<br><br>

We will attempt to block the Ubuntu machine from pinging 8.8.8.8 using `agent_control`. However, before implementing the block, we will first verify that the Ubuntu machine can successfully ping 8.8.8.8.<br><br>
`ping 8.8.8.8`<br><br>
![image](https://github.com/user-attachments/assets/4e0f8519-6b2d-4a32-97fc-da61a2507922)<br><br>
Now, let's execute the active response command.<br><br>

`./agent_control -b 8.8.8.8 -f firewall-drop0 -u 002`<br><br>
`-b 8.8.8.8`: Specifies the IP address to be targeted by the active response<br><br>

`-f firewall-drop0`: Indicates the active response command to execute. firewall-drop is a standard script in Wazuh designed to block IP addresses using the system's firewall<br><br>

`-u 002`: Identifies the agent by its unique ID (002) on which the active response should be executed.​<br><br>
![image](https://github.com/user-attachments/assets/f32dcdac-dee8-4ceb-b96f-72fe614c5c9c)<br><br>
![image](https://github.com/user-attachments/assets/0ec0d9e2-d602-4665-952b-e33d59755c1f)<br><br>
Next, let's try to ping 8.8.8.8 from the Ubuntu machine.<br><br>
![image](https://github.com/user-attachments/assets/f476988e-1e63-43bd-a6d5-a1923316308b)<br><br>
Let's confirm this by reviewing the firewall rules.<br><br>

`sudo iptables --list`<br><br>
![image](https://github.com/user-attachments/assets/01685d3a-75c3-4651-aa51-8bfc6ea6451a)<br><br>
We can also review the logs of the active response from this location.<br><br>

`cat /var/ossec/logs/active-responses.log`<br><br>
![image](https://github.com/user-attachments/assets/84aaa113-f027-4d58-b3b0-8047a1e04ad2)<br><br>
Now, let's return to our Shuffle workflow and utilize an HTTP app to retrieve the Wazuh API JWT.<br><br>

However, obtaining the API JWT requires access to the necessary credentials.<br><br>
![image](https://github.com/user-attachments/assets/fd68da01-ea7e-42b6-a0ba-32dc460c6321)<br><br>
During the Wazuh installation process, we previously downloaded this file. We now need to extract it in order to retrieve the credentials required to obtain the JWT.<br><br>

`tar -xvf wazuh-install-files.tar`<br><br>
![image](https://github.com/user-attachments/assets/a2e251e4-d84b-45ca-bbe4-2d90336d7cca)<br><br>
You can find the necessary credentials in the file wazuh-passwords.txt.<br><br>

We can get the JWT we need using the following command:<br><br>

`curl -u username:password -k -X GET "https://192.168.204.150:55000/security/user/authenticate?raw=true`<br><br>
Let's proceed with this on Shuffle. However, before doing so, let's remove the rule that blocks ping requests to 8.8.8.8 on the Ubuntu machine. Once the rule is removed, we can attempt the same scenario using Shuffle.<br><br>

`sudo iptables -L -n -v --line-numbers`<br><br>
![image](https://github.com/user-attachments/assets/2613c49a-f25a-4deb-8728-fe21a4807bb3)<br><br>
`sudo iptables -D INPUT 1`<br><br>
`sudo iptables -D INPUT 1`<br><br>
![image](https://github.com/user-attachments/assets/f87035bb-4177-48cf-9949-aaf56c206410)<br><br>
`ping 8.8.8.8`<br><br>
![image](https://github.com/user-attachments/assets/b7d9ba8d-418c-43db-879f-94dc0b84c5df)<br><br>
Now, let's attempt to block the IP using the Shuffle workflow.<br><br>
![image](https://github.com/user-attachments/assets/92a8a5da-3b28-4f36-8dcf-6a385275ddb7)<br><br>
![image](https://github.com/user-attachments/assets/7170bf3a-0275-4bdf-8dc6-9aaf7010fbeb)<br><br>
You will need to enter your IP address, username, and password.<br><br>
![image](https://github.com/user-attachments/assets/61927b06-5163-4429-83a9-e23aa3cc1e39)<br><br>
Now, let's integrate the Wazuh application into our workflow.<br><br>
![image](https://github.com/user-attachments/assets/a2d7e063-a636-4d45-b108-13bc2da0eb4c)<br><br>
![image](https://github.com/user-attachments/assets/dccb20f5-6cba-4800-b96e-4635cdb23000)<br><br>
![image](https://github.com/user-attachments/assets/afbdab77-5678-42de-a86e-cb0a0b5f0b87)<br><br>
![image](https://github.com/user-attachments/assets/2c2beb91-831e-4645-ae33-41b04c809200)<br><br>
Let's save the changes and execute the workflow again.<br><br>
![image](https://github.com/user-attachments/assets/50d027c9-b88a-4513-aa2c-21322bfd5af7)<br><br>
![image](https://github.com/user-attachments/assets/b2b50c90-8f8a-436e-a6d5-0c91ae7fd9f2)<br><br>
Let's verify whether the Ubuntu machine can successfully ping 8.8.8.8.<br><br>
`ping 8.8.8.8`<br><br>
![image](https://github.com/user-attachments/assets/e495f42d-16ff-46bd-a981-02c3c0858dd3)<br><br>

`iptables -L`<br><br>
![image](https://github.com/user-attachments/assets/5c400df3-ae0e-4359-945d-694d897c5567)<br><br>
Let's incorporate the user input trigger into our workflow to send an email to the analyst, allowing them to decide whether to block the IP address.<br><br>

Before utilizing the user input trigger, let's first create a new workflow named "Send an Alert." This workflow will be used to send an alert via a Telegram bot.<br><br>
![image](https://github.com/user-attachments/assets/73a60df2-afd6-4d4e-8250-3c0664510c56)<br><br>
Next, after saving the workflow, we will incorporate the user input trigger into the process.<br><br>
![image](https://github.com/user-attachments/assets/4e05a738-59c8-4161-be4c-3307031dc636)<br><br>

Let's configure the Wazuh application to dynamically assign the source IP.<br><br>
`{"data":{"srcip":"$exec.all_fields.data.srcip"}}`<br><br>
![image](https://github.com/user-attachments/assets/994eaa98-3b0f-4aaa-bbf5-969b364676cf)<br><br>
![image](https://github.com/user-attachments/assets/114c8712-f48a-4904-9e92-a503c973d831)<br><br>
![image](https://github.com/user-attachments/assets/6891fb10-7155-48d0-bb29-d77f7a278f77)<br><br>
Now, let's review the other workflow to ensure everything is functioning correctly.<br><br>
![image](https://github.com/user-attachments/assets/04760a43-3cc7-4b3c-95cf-ae005cea9281)<br><br>
We now need to integrate the Telegram app into this workflow to send the alert to the analyst.<br><br>
Note: everything can use that<br><br>

Now that we have blocked the IP address 192.168.204.151 from attacking the Ubuntu machine at 192.168.204.146, let's verify whether the attacker can still ping the Ubuntu machine.<br><br>

`ping 192.168.204.146`<br><br>
![image](https://github.com/user-attachments/assets/6f7ef03c-6f95-4725-9dcd-90315e998de8)<br><br>
Let's also review the firewall rules on the Ubuntu machine.<br><br>
`iptables -L`<br><br>
![image](https://github.com/user-attachments/assets/ced820ef-7c15-4592-96fd-e1653ab0156b)<br><br>
Let's also generate and send an alert to TheHive.<br><br>
![image](https://github.com/user-attachments/assets/41f3c3ac-bebf-44b9-b5fe-0e0db8385680)<br><br>
![image](https://github.com/user-attachments/assets/7d6a1cdf-ff25-4dc8-9068-bc483d61b1d9)<br><br>

`Summary -> Multiple SSH login attempts using non-existent usernames on host: $exec.all_fields.predecoder.hostname from source IP:$exec.all_fields.data.srcip`<br><br>

![image](https://github.com/user-attachments/assets/21843177-f60c-413e-ab8d-2de808cca402)<br><br>
![image](https://github.com/user-attachments/assets/c444f77e-6662-4707-8c58-5eb84db1203d)<br><br>
Now, let's save the changes and execute the workflow again.<br><br>
![image](https://github.com/user-attachments/assets/d54d5218-4f12-45be-881a-996ea65152fd)<br><br>
![image](https://github.com/user-attachments/assets/3d7a55ea-f13c-41bb-964d-faaffb9b18dc)<br><br>
I hope the project was clear and easy to understand. Thank you for Reading<br><br>
<hr>

