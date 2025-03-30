# Device Accidentally Exposed to the Internet

<center>
  <img src="https://github.com/user-attachments/assets/51a58402-c790-43b5-bc4f-9bae74235f85" width="600" height="600">
</center>

---

## 📚 **Scenario:**  
During routine security maintenance, the security team was tasked with investigating any VMs in the shared services cluster that might have been mistakenly exposed to the public internet. The focus was on identifying misconfigured VMs and checking for potential brute-force login attempts from external sources.

## 🔍 Hypothesis
1. Exposed VMs are susceptible to brute-force login attempts from malicious external actors.
2. Older VMs or configurations that lack modern security controls—such as account lockout policies, MFA (multi-factor authentication), or hardened credential mechanisms—are at a heightened risk of compromise.

---

## 📊 **Incident Summary and Findings** 

### 📝 Query 1: Identify Internet-Facing Devices
```kql
DeviceInfo
| where DeviceName == "whibbert-edr-md"
| where IsInternetFacing == true
| project Timestamp, DeviceId, DeviceName
| order by Timestamp desc
```

**Findings:**
- Investigation date: **March 29, 2025.**
- The `whibbert-edr-md` VM was **not directly internet-facing** at the time of the investigation.
- However, previous day showed device was found to be internet-facing for some time. 
  
![image](https://github.com/user-attachments/assets/8b4a3583-43b2-418a-bc4c-d8920bce792d)


---

## 🚀 Data Analysis

### 📝 Query 2: Identify Failed Login Attempts from Remote IPs
```kql
DeviceLogonEvents
| where DeviceName == "whibbert-edr-md"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| extend GeoInfo = geo_info_from_ip_address(RemoteIP)
| extend Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName, Country, City
| order by Attempts desc
```

**Findings:**
- Multiple failed login attempts were detected from **various remote IP addresses and countries**.
- The top three (3) attacking IPs were:
  - `190.181.24.50`
  - `5.178.87.180`
  - `77.223.118.28`

![image](https://github.com/user-attachments/assets/c18ffa41-e643-42b9-8722-e53bcac23701)

<br>

### 📝 Query 3: Check for Successful Logins from Malicious IPs
```kql
let RemoteIPsInQuestion = dynamic(["190.181.24.50", "5.178.87.180", "77.223.118.28"]);
DeviceLogonEvents
| where DeviceName == "whibbert-edr-md"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
| project Timestamp, DeviceName, RemoteIP, AccountName
| order by Timestamp desc
```

**Findings:**
- No successful logins from the identified malicious IPs.

![image](https://github.com/user-attachments/assets/db1513cb-e13e-445f-99de-4105d8fdcae9)

<br>

### 📝 Query 4: Identify All Successful Logins to the VM
```kql
DeviceLogonEvents
| where DeviceName == "whibbert-edr-md"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
```

**Findings:**
- The only successful remote/network logins in the last 30 days were from the `whibbert` account (4 times).
- **No failed login attempts for this account**, meaning no brute force attacks were successful against it.

---

## ⚡ Investigation Insights
Although the `whibbert-edr-md` VM was not explicitly internet-facing, attackers **still attempted brute force logins** due to automated Azure IP range scanning.

### 🔎 How did attackers find the VM?
- Attackers use **automated scanners** to probe Azure’s public IP ranges.
- Even without a direct public IP, authentication logs recorded these attempts at **Azure’s authentication layer** before reaching the VM.

### 🔎 **Relevant MITRE ATT&CK TTPs**
| **TTP ID** | **Technique** | **Description** |
|------------|--------------|----------------|
| **T1595**  | **Active Scanning** | Attackers scanned Azure’s public IP ranges looking for exposed services. |
| **T1110**  | **Brute Force** | Multiple failed login attempts indicate systematic credential guessing. |

---

## 🛡️ Response & Mitigation

### ✅ **Recommended Mitigation Strategies**

#### 🔹 **To Prevent Exposure to Active Scanning (T1595)**
✔️ Restrict network exposure with **firewalls, VPNs, or load balancers**.  
✔️ Configure **Network Security Groups (NSGs)** to **allow RDP only from trusted sources**.  
✔️ Implement **intrusion detection systems (IDS/IPS)** to detect and block scanning traffic.  
✔️ Minimize exposed services by placing **critical systems behind private networks**.  

#### 🔹 **To Mitigate Brute Force Attacks (T1110)**
✔️ Enforce **Multi-Factor Authentication (MFA)** on all accounts.  
✔️ Configure **account lockout policies** to prevent repeated failed login attempts.  
✔️ Implement **Just-In-Time (JIT) access** to restrict open management ports.  
✔️ Continuously monitor authentication logs for unusual login activity.  

---

## ✨ Areas for Improvement

### 🔹 **Security Enhancements**
- Implement **proactive network segmentation** to reduce attack surfaces.
- Enhance **Azure NSG policies** to block unwanted traffic more effectively.

### 🔹 **Threat Hunting Improvements**
- Improve **KQL proficiency** for more efficient detection of attack patterns.
- Automate security monitoring with **custom alerts and SIEM integrations**.

---

## 📋 Final Summary
✅ The `whibbert-edr-md` VM was **targeted by automated brute-force attacks**, but no successful intrusions occurred.  
✅ Attackers leveraged **T1595 (Active Scanning)** to detect Azure VMs and **T1110 (Brute Force)** to attempt logins.  
✅ **No malicious actors successfully logged in**, but the event highlights the importance of **proactive cloud security**. 

🔐 **Next Steps**:
- **Strengthen network security controls**: Configure firewalls, use private endpoints, and apply IP whitelisting and geo-fencing.
- **MFA enforcement**: Ensure MFA is mandatory for privileged accounts and use Conditional Access policies.
- **Log Monitoring**: Implement SIEM tools for real-time alerts and regularly audit Azure AD and authentication logs.  

---

## Created By:
- **Author Name**: Winston Hibbert
- **Author Contact**: www.linkedin.com/in/winston-hibbert-262a44271/
- **Date**: March 28, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 28, 2025`  | `Winston Hibbert`  
