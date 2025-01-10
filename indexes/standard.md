## Panther Standard Detections

### Supported Log Types are listed below each detection

[Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)  
Assigning an admin role manually could be a sign of privilege escalation
  - Asana
  - Zendesk
  - Google Workspace
  - GCP
  - OneLogin
  - GitHub
  - Atlassian


[Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)  
An actor user was denied login access more times than the configured threshold.
  - Okta
  - Asana
  - OnePassword
  - Google Workspace
  - OneLogin
  - Atlassian
  - Box
  - AWS CloudTrail


[DNS Base64 Encoded Query](../rules/standard_rules/standard_dns_base64.yml)  
Detects DNS queries with Base64 encoded subdomains, which could indicate an attempt to obfuscate data exfil.
  - CiscoUmbrella
  - Crowdstrike
  - AWS VPCDns


[Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)  
A user has subsequent logins from two geographic locations that are very far apart
  - Notion
  - AWS CloudTrail
  - Asana
  - Okta


[Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)  
The rule looks for DNS requests to sites potentially posing as SSO domains.
  - CiscoUmbrella
  - Zeek
  - Crowdstrike
  - Suricata


[MFA Disabled](../rules/standard_rules/mfa_disabled.yml)  
Detects when Multi-Factor Authentication (MFA) is disabled
  - Okta
  - GitHub
  - Zendesk
  - Atlassian


[Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)  
Detects when an entity signs in from a nation associated with cyber attacks
  - Azure
  - Zoom
  - Okta
  - Asana
  - OnePassword
  - Zendesk
  - OneLogin
  - Atlassian
  - Box
  - Notion
  - AWS CloudTrail


