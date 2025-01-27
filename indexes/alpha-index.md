# Alpha Index

- [A](#A)
- [B](#B)
- [C](#C)
- [D](#D)
- [G](#G)
- [M](#M)
- [N](#N)
- [O](#O)
- [P](#P)
- [S](#S)
- [T](#T)
- [W](#W)
- [Z](#Z)
# A

- [AWS ACM](#aws-acm)
- [AWS CloudFormation](#aws-cloudformation)
- [AWS CloudTrail](#aws-cloudtrail)
- [AWS CloudWatch](#aws-cloudwatch)
- [AWS Config](#aws-config)
- [AWS DynamoDB](#aws-dynamodb)
- [AWS EC2](#aws-ec2)
- [AWS EKS](#aws-eks)
- [AWS ELBV2](#aws-elbv2)
- [AWS GuardDuty](#aws-guardduty)
- [AWS IAM](#aws-iam)
- [AWS KMS](#aws-kms)
- [AWS PasswordPolicy](#aws-passwordpolicy)
- [AWS RDS](#aws-rds)
- [AWS Redshift](#aws-redshift)
- [AWS S3](#aws-s3)
- [AWS S3ServerAccess](#aws-s3serveraccess)
- [AWS SecurityFindingFormat](#aws-securityfindingformat)
- [AWS VPCDns](#aws-vpcdns)
- [AWS VPCFlow](#aws-vpcflow)
- [AWS WAF](#aws-waf)
- [AppOmni](#appomni)
- [Asana](#asana)
- [Atlassian](#atlassian)
- [Auth0](#auth0)
- [Azure](#azure)


## AWS ACM

- [AWS ACM Certificate Expiration](../policies/aws_acm_policies/aws_acm_certificate_expiration.yml)
- [AWS ACM Certificate Status](../policies/aws_acm_policies/aws_acm_certificate_valid.yml)
- [AWS ACM Secure Algorithms](../policies/aws_acm_policies/aws_acm_certificate_has_secure_algorithms.yml)


## AWS CloudFormation

- [AWS CloudFormation Stack Drift](../policies/aws_cloudformation_policies/aws_cloudformation_stack_drifted.yml)
- [AWS CloudFormation Stack IAM Service Role](../policies/aws_cloudformation_policies/aws_cloudformation_stack_uses_iam_role.yml)
- [AWS CloudFormation Stack Termination Protection](../policies/aws_cloudformation_policies/aws_cloudformation_termination_protection.yml)


## AWS CloudTrail

- [A CloudTrail Was Created or Updated](../rules/aws_cloudtrail_rules/aws_cloudtrail_created.yml)
- [Account Security Configuration Changed](../rules/aws_cloudtrail_rules/aws_security_configuration_change.yml)
- [Amazon Machine Image (AMI) Modified to Allow Public Access](../rules/aws_cloudtrail_rules/aws_ami_modified_for_public_access.yml)
- [Anomalous AccessDenied Requests](../queries/aws_queries/anomalous_access_denied_query.yml)
- [AWS Access Key Uploaded to Github](../rules/aws_cloudtrail_rules/aws_key_compromised.yml)
- [AWS Authentication From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device.yml)
- [AWS Authentication from CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/aws_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device_FDREvent.yml)
- [AWS CloudTrail Account Discovery](../rules/aws_cloudtrail_rules/aws_cloudtrail_account_discovery.yml)
- [AWS CloudTrail CloudWatch Logs](../policies/aws_cloudtrail_policies/aws_cloudtrail_cloudwatch_logs.yml)
- [AWS CloudTrail Log Encryption](../policies/aws_cloudtrail_policies/aws_cloudtrail_log_encryption.yml)
- [AWS CloudTrail Log Validation](../policies/aws_cloudtrail_policies/aws_cloudtrail_log_validation.yml)
- [AWS CloudTrail Management Events Enabled](../policies/aws_cloudtrail_policies/aws_cloudtrail_enabled.yml)
- [AWS CloudTrail Password Policy Discovery](../rules/aws_cloudtrail_rules/aws_cloudtrail_password_policy_discovery.yml)
- [AWS CloudTrail Retention Lifecycle Too Short](../rules/aws_cloudtrail_rules/aws_cloudtrail_short_lifecycle.yml)
- [AWS CloudTrail S3 Bucket Access Logging](../policies/aws_cloudtrail_policies/aws_cloudtrail_s3_bucket_access_logging.yml)
- [AWS CloudTrail S3 Bucket Public](../policies/aws_cloudtrail_policies/aws_cloudtrail_s3_bucket_public.yml)
- [AWS Compromised IAM Key Quarantine](../rules/aws_cloudtrail_rules/aws_iam_compromised_key_quarantine.yml)
- [AWS Config Service Created](../rules/aws_cloudtrail_rules/aws_config_service_created.yml)
- [AWS Config Service Disabled](../rules/aws_cloudtrail_rules/aws_config_service_disabled_deleted.yml)
- [AWS Console Login](../rules/aws_cloudtrail_rules/aws_console_login.yml)
- [AWS Console Sign-In NOT PRECEDED BY Okta Redirect](../correlation_rules/aws_console_sign-in_without_okta.yml)
- [AWS DNS Logs Deleted](../rules/aws_cloudtrail_rules/aws_dns_logs_deleted.yml)
- [AWS EC2 EBS Encryption Disabled](../rules/aws_cloudtrail_rules/aws_ec2_ebs_encryption_disabled.yml)
- [AWS EC2 Image Monitoring](../rules/aws_cloudtrail_rules/aws_ec2_monitoring.yml)
- [AWS EC2 Manual Security Group Change](../rules/aws_cloudtrail_rules/aws_ec2_manual_security_group_changes.yml)
- [AWS EC2 Startup Script Change](../rules/aws_cloudtrail_rules/aws_ec2_startup_script_change.yml)
- [AWS EC2 Traffic Mirroring](../rules/aws_cloudtrail_rules/aws_ec2_traffic_mirroring.yml)
- [AWS EC2 Vulnerable XZ Image Launched](../rules/aws_cloudtrail_rules/aws_ec2_vulnerable_xz_image_launched.yml)
- [AWS ECR Events](../rules/aws_cloudtrail_rules/aws_ecr_events.yml)
- [AWS IAM Group Read Only Events](../rules/aws_cloudtrail_rules/aws_iam_group_read_only_events.yml)
- [AWS Macie Disabled/Updated](../rules/aws_cloudtrail_rules/aws_macie_evasion.yml)
- [AWS Modify Cloud Compute Infrastructure](../rules/aws_cloudtrail_rules/aws_modify_cloud_compute_infrastructure.yml)
- [AWS Network ACL Overly Permissive Entry Created](../rules/aws_cloudtrail_rules/aws_network_acl_permissive_entry.yml)
- [AWS Potentially Stolen Service Role](../queries/aws_queries/aws_potentially_compromised_service_role_query.yml)
- [AWS Privilege Escalation Via User Compromise](../correlation_rules/aws_privilege_escalation_via_user_compromise.yml)
- [AWS Public RDS Restore](../rules/aws_cloudtrail_rules/aws_rds_publicrestore.yml)
- [AWS RDS Manual/Public Snapshot Created](../rules/aws_cloudtrail_rules/aws_rds_manual_snapshot_created.yml)
- [AWS RDS Master Password Updated](../rules/aws_cloudtrail_rules/aws_rds_master_pass_updated.yml)
- [AWS RDS Snapshot Shared](../rules/aws_cloudtrail_rules/aws_rds_snapshot_shared.yml)
- [AWS Resource Made Public](../rules/aws_cloudtrail_rules/aws_resource_made_public.yml)
- [AWS S3 Bucket Policy Modified](../rules/aws_cloudtrail_rules/aws_s3_bucket_policy_modified.yml)
- [AWS SAML Activity](../rules/aws_cloudtrail_rules/aws_saml_activity.yml)
- [AWS SecurityHub Finding Evasion](../rules/aws_cloudtrail_rules/aws_securityhub_finding_evasion.yml)
- [AWS Snapshot Made Public](../rules/aws_cloudtrail_rules/aws_snapshot_made_public.yml)
- [AWS Software Discovery](../rules/aws_cloudtrail_rules/aws_software_discovery.yml)
- [AWS SSO Access Token Retrieved by Unauthenticated IP](../correlation_rules/aws_sso_access_token_retrieved_by_unauthenticated_ip.yml)
- [AWS Trusted IPSet Modified](../rules/aws_cloudtrail_rules/aws_ipset_modified.yml)
- [AWS Unsuccessful MFA attempt](../rules/aws_cloudtrail_rules/aws_cloudtrail_unsuccessful_mfa_attempt.yml)
- [AWS User API Key Created](../rules/aws_cloudtrail_rules/aws_iam_user_key_created.yml)
- [AWS User Login Profile Created or Modified](../rules/aws_cloudtrail_rules/aws_cloudtrail_loginprofilecreatedormodified.yml)
- [AWS User Login Profile Modified](../rules/aws_cloudtrail_rules/aws_user_login_profile_modified.yml)
- [AWS User Takeover Via Password Reset](../correlation_rules/aws_user_takeover_via_password_reset.yml)
- [AWS VPC Flow Logs Removed](../rules/aws_cloudtrail_rules/aws_vpc_flow_logs_deleted.yml)
- [AWS WAF Disassociation](../rules/aws_cloudtrail_rules/aws_waf_disassociation.yml)
- [AWS.CloudTrail.UserAccessKeyAuth](../rules/aws_cloudtrail_rules/aws_cloudtrail_useraccesskeyauth.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [CloudTrail EC2 StopInstances](../rules/aws_cloudtrail_rules/aws_ec2_stopinstances.yml)
- [CloudTrail Event Delectors Disabled](../rules/aws_cloudtrail_rules/aws_cloudtrail_event_selectors_disabled.yml)
- [CloudTrail Password Spraying](../queries/aws_queries/cloudtrail_password_spraying.yml)
- [CloudTrail Stopped](../rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.yml)
- [CodeBuild Project made Public](../rules/aws_cloudtrail_rules/aws_codebuild_made_public.yml)
- [Detect Reconnaissance from IAM Users](../rules/aws_cloudtrail_rules/aws_iam_user_recon_denied.yml)
- [EC2 Network ACL Modified](../rules/aws_cloudtrail_rules/aws_ec2_network_acl_modified.yml)
- [EC2 Network Gateway Modified](../rules/aws_cloudtrail_rules/aws_ec2_gateway_modified.yml)
- [EC2 Route Table Modified](../rules/aws_cloudtrail_rules/aws_ec2_route_table_modified.yml)
- [EC2 Security Group Modified](../rules/aws_cloudtrail_rules/aws_ec2_security_group_modified.yml)
- [EC2 VPC Modified](../rules/aws_cloudtrail_rules/aws_ec2_vpc_modified.yml)
- [ECR CRUD Actions](../rules/aws_cloudtrail_rules/aws_ecr_crud.yml)
- [Failed Root Console Login](../rules/aws_cloudtrail_rules/aws_console_root_login_failed.yml)
- [IAM Assume Role Blocklist Ignored](../rules/aws_cloudtrail_rules/aws_iam_assume_role_blocklist_ignored.yml)
- [IAM Change](../rules/aws_cloudtrail_rules/aws_iam_anything_changed.yml)
- [IAM Entity Created Without CloudFormation](../rules/aws_cloudtrail_rules/aws_iam_entity_created_without_cloudformation.yml)
- [IAM Policy Modified](../rules/aws_cloudtrail_rules/aws_iam_policy_modified.yml)
- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
- [KMS CMK Disabled or Deleted](../rules/aws_cloudtrail_rules/aws_kms_cmk_loss.yml)
- [Lambda CRUD Actions](../rules/aws_cloudtrail_rules/aws_lambda_crud.yml)
- [Logins Without MFA](../rules/aws_cloudtrail_rules/aws_console_login_without_mfa.yml)
- [Logins Without SAML](../rules/aws_cloudtrail_rules/aws_console_login_without_saml.yml)
- [Monitor Unauthorized API Calls](../rules/aws_cloudtrail_rules/aws_unauthorized_api_call.yml)
- [New AWS Account Created](../rules/indicator_creation_rules/new_aws_account_logging.yml)
- [New IAM Credentials Updated](../rules/aws_cloudtrail_rules/aws_update_credentials.yml)
- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
- [RoleAssumes by Multiple Useragents](../queries/aws_queries/anomalous_role_assume_query.yml)
- [Root Account Access Key Created](../rules/aws_cloudtrail_rules/aws_root_access_key_created.yml)
- [Root Account Activity](../rules/aws_cloudtrail_rules/aws_root_activity.yml)
- [Root Console Login](../rules/aws_cloudtrail_rules/aws_console_root_login.yml)
- [Root Password Changed](../rules/aws_cloudtrail_rules/aws_root_password_changed.yml)
- [S3 Bucket Deleted](../rules/aws_cloudtrail_rules/aws_s3_bucket_deleted.yml)
- [Secret Exposed and not Quarantined](../correlation_rules/secret_exposed_and_not_quarantined.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
- [StopInstance FOLLOWED BY ModifyInstanceAttributes](../correlation_rules/aws_cloudtrail_stopinstance_followed_by_modifyinstanceattributes.yml)
- [Unused AWS Region](../rules/aws_cloudtrail_rules/aws_unused_region.yml)


## AWS CloudWatch

- [AWS CloudWatch Log Encryption](../policies/aws_cloudwatch_policies/aws_cloudwatch_loggroup_encrypted.yml)
- [AWS CloudWatch Logs Data Retention](../policies/aws_cloudwatch_policies/aws_cloudwatch_loggroup_data_retention.yml)
- [Sensitive AWS CloudWatch Log Encryption](../policies/aws_cloudwatch_policies/aws_cloudwatch_loggroup_sensitive_encrypted.yml)


## AWS Config

- [AWS Config Global Resources](../policies/aws_config_policies/aws_config_global_resources.yml)
- [AWS Config Recording Status](../policies/aws_config_policies/aws_config_recording_no_error.yml)
- [AWS Config Records All Resource Types](../policies/aws_config_policies/aws_config_all_resource_types.yml)
- [AWS Config Status](../policies/aws_config_policies/aws_config_recording_enabled.yml)


## AWS DynamoDB

- [AWS DynamoDB Table Autoscaling](../policies/aws_dynamodb_policies/aws_dynamodb_autoscaling.yml)
- [AWS DynamoDB Table Autoscaling Configuration](../policies/aws_dynamodb_policies/aws_dynamodb_autoscaling_configuration.yml)
- [AWS DynamoDB Table TTL](../policies/aws_dynamodb_policies/aws_dynamodb_table_ttl_enabled.yml)


## AWS EC2

- [AWS AMI Sharing](../policies/aws_ec2_policies/aws_ami_private.yml)
- [AWS CDE EC2 Volume Encryption](../policies/aws_ec2_policies/aws_ec2_cde_volume_encrypted.yml)
- [AWS EC2 AMI Approved Host](../policies/aws_ec2_policies/aws_ec2_ami_approved_host.yml)
- [AWS EC2 AMI Approved Instance Type](../policies/aws_ec2_policies/aws_ec2_ami_approved_instance_type.yml)
- [AWS EC2 AMI Approved Tenancy](../policies/aws_ec2_policies/aws_ec2_ami_approved_tenancy.yml)
- [AWS EC2 Instance Approved AMI](../policies/aws_ec2_policies/aws_ec2_instance_approved_ami.yml)
- [AWS EC2 Instance Approved Host](../policies/aws_ec2_policies/aws_ec2_instance_approved_host.yml)
- [AWS EC2 Instance Approved Instance Type](../policies/aws_ec2_policies/aws_ec2_instance_approved_instance_type.yml)
- [AWS EC2 Instance Approved Tenancy](../policies/aws_ec2_policies/aws_ec2_instance_approved_tenancy.yml)
- [AWS EC2 Instance Approved VPC](../policies/aws_ec2_policies/aws_ec2_instance_approved_vpc.yml)
- [AWS EC2 Instance Detailed Monitoring](../policies/aws_ec2_policies/aws_ec2_instance_detailed_monitoring.yml)
- [AWS EC2 Instance EBS Optimization](../policies/aws_ec2_policies/aws_ec2_instance_ebs_optimization.yml)
- [AWS EC2 Volume Encryption](../policies/aws_ec2_policies/aws_ec2_volume_encryption.yml)
- [AWS EC2 Volume Snapshot Encryption](../policies/aws_ec2_policies/aws_ec2_volume_snapshot_encrypted.yml)
- [AWS Network ACL Restricts Inbound Traffic](../policies/aws_vpc_policies/aws_network_acl_restricts_inbound_traffic.yml)
- [AWS Network ACL Restricts Insecure Protocols](../policies/aws_vpc_policies/aws_network_acl_restricts_insecure_protocols.yml)
- [AWS Network ACL Restricts Outbound Traffic](../policies/aws_vpc_policies/aws_network_acl_restricts_outbound_traffic.yml)
- [AWS Network ACL Restricts SSH](../policies/aws_vpc_policies/aws_network_acl_restricted_ssh.yml)
- [AWS Resource Minimum Tags ](../policies/aws_account_policies/aws_resource_minimum_tags.yml)
- [AWS Resource Required Tags](../policies/aws_account_policies/aws_resource_required_tags.yml)
- [AWS Security Group - Only DMZ Publicly Accessible](../policies/aws_vpc_policies/aws_only_dmz_security_groups_publicly_accessible.yml)
- [AWS Security Group Administrative Ingress](../policies/aws_vpc_policies/aws_security_group_administrative_ingress.yml)
- [AWS Security Group Restricts Access To CDE](../policies/aws_vpc_policies/aws_security_group_restricts_access_to_cde.yml)
- [AWS Security Group Restricts Inbound Traffic](../policies/aws_vpc_policies/aws_security_group_restricts_inbound_traffic.yml)
- [AWS Security Group Restricts Inter-SG Traffic](../policies/aws_vpc_policies/aws_security_group_restricts_inter_security_group_traffic.yml)
- [AWS Security Group Restricts Outbound Traffic](../policies/aws_vpc_policies/aws_security_group_restricts_outbound_traffic.yml)
- [AWS Security Group Restricts Traffic Leaving CDE](../policies/aws_vpc_policies/aws_security_group_restricts_traffic_leaving_cde.yml)
- [AWS Security Group Tightly Restricts Inbound Traffic](../policies/aws_vpc_policies/aws_security_group_tightly_restricts_inbound_traffic.yml)
- [AWS Security Group Tightly Restricts Outbound Traffic](../policies/aws_vpc_policies/aws_security_group_tightly_restricts_outbound_traffic.yml)
- [AWS VPC Default Network ACL Restricts All Traffic](../policies/aws_vpc_policies/aws_vpc_default_network_acl_restricts_all_traffic.yml)
- [AWS VPC Default Security Group Restrictions ](../policies/aws_vpc_policies/aws_vpc_default_security_restrictions.yml)
- [AWS VPC Flow Logs](../policies/aws_vpc_policies/aws_vpc_flow_logs.yml)


## AWS EKS

- [EKS Anonymous API Access Detected](../rules/aws_eks_rules/anonymous_api_access.yml)
- [EKS Audit Log based single sourceIP is generating multiple 403s](../rules/aws_eks_rules/source_ip_multiple_403.yml)
- [EKS Audit Log Reporting system Namespace is Used From A Public IP](../rules/aws_eks_rules/system_namespace_public_ip.yml)
- [IOC Activity in K8 Control Plane](../queries/kubernetes_queries/kubernetes_ioc_activity.yml)
- [Kubernetes Cron Job Created or Modified](../queries/kubernetes_queries/kubernetes_cron_job_created_or_modified.yml)
- [Kubernetes Pod Created in Pre-Configured or Default Name Spaces](../queries/kubernetes_queries/kubernetes_pod_in_default_name_space_query.yml)
- [New Admission Controller Created](../queries/kubernetes_queries/kubernetes_admission_controller_created_query.yml)
- [New DaemonSet Deployed to Kubernetes](../queries/kubernetes_queries/kubernetes_new_daemonset_deployed.yml)
- [Pod attached to the Node Host Network](../queries/kubernetes_queries/kubernetes_pod_attached_to_node_host_network.yml)
- [Pod Created or Modified Using the Host IPC Namespace](../queries/kubernetes_queries/kubernetes_pod_using_host_ipc_namespace_query.yml)
- [Pod Created or Modified Using the Host PID Namespace](../queries/kubernetes_queries/kubernetes_pod_using_host_pid_namespace_query.yml)
- [Pod Created with Overly Permissive Linux Capabilities](../queries/kubernetes_queries/kubernetes_overly_permissive_linux_capabilities.yml)
- [Pod creation or modification to a Host Path Volume Mount](../queries/kubernetes_queries/kubernetes_pod_create_or_modify_host_path_vol_mount.yml)
- [Privileged Pod Created](../queries/kubernetes_queries/kubernetes_privileged_pod_created.yml)
- [Secret Enumeration by a User](../queries/kubernetes_queries/kubernetes_secret_enumeration.yml)
- [Unauthenticated Kubernetes API Request](../queries/kubernetes_queries/kubernetes_unauthenticated_api_request.yml)
- [Unauthorized Kubernetes Pod Execution](../queries/kubernetes_queries/kubernetes_unauthorized_pod_execution_query.yml)


## AWS ELBV2

- [AWS Application Load Balancer Web ACL](../policies/aws_elb_policies/aws_application_load_balancer_web_acl.yml)
- [AWS ELB SSL Policies](../policies/aws_load_balancer_policies/aws_alb_ssl_policy.yml)
- [AWS Enforces SSL Policies](../policies/aws_load_balancer_policies/aws_elbv2_load_balancer_has_ssl_policy.yml)


## AWS GuardDuty

- [AWS GuardDuty Enabled](../policies/aws_guardduty_policies/aws_guardduty_enabled.yml)
- [AWS GuardDuty High Severity Finding](../rules/aws_guardduty_rules/aws_guardduty_high_sev_findings.yml)
- [AWS GuardDuty Low Severity Finding](../rules/aws_guardduty_rules/aws_guardduty_low_sev_findings.yml)
- [AWS GuardDuty Master Account](../policies/aws_guardduty_policies/aws_guardduty_master_account.yml)
- [AWS GuardDuty Medium Severity Finding](../rules/aws_guardduty_rules/aws_guardduty_med_sev_findings.yml)


## AWS IAM

- [AWS Access Key Rotation](../policies/aws_iam_policies/aws_access_key_rotation.yml)
- [AWS Access Keys At Account Creation](../policies/aws_iam_policies/aws_access_keys_at_account_creation.yml)
- [AWS CloudTrail Least Privilege Access](../policies/aws_iam_policies/aws_cloudtrail_least_privilege.yml)
- [AWS IAM Group Users](../policies/aws_iam_policies/aws_iam_group_users.yml)
- [AWS IAM Password Unused](../policies/aws_iam_policies/aws_password_unused.yml)
- [AWS IAM Policy Administrative Privileges](../policies/aws_iam_policies/aws_iam_policy_administrative_privileges.yml)
- [AWS IAM Policy Assigned to User](../policies/aws_iam_policies/aws_iam_policy_assigned_to_user.yml)
- [AWS IAM Policy Blocklist](../policies/aws_iam_policies/aws_iam_policy_blocklist.yml)
- [AWS IAM Policy Does Not Grant Any Administrative Access](../policies/aws_iam_policies/aws_iam_policy_does_not_grant_admin_access.yml)
- [AWS IAM Policy Does Not Grant Network Admin Access](../policies/aws_iam_policies/aws_iam_policy_does_not_grant_network_admin_access.yml)
- [AWS IAM Policy Role Mapping](../policies/aws_iam_policies/aws_iam_policy_role_mapping.yml)
- [AWS IAM Resource Does Not Have Inline Policy](../policies/aws_iam_policies/aws_iam_resource_does_not_have_inline_policy.yml)
- [AWS IAM Role Grants (permission) to Non-organizational Account](../policies/aws_iam_policies/aws_iam_role_external_permission.yml)
- [AWS IAM Role Restricts Usage](../policies/aws_iam_policies/aws_iam_role_restricts_usage.yml)
- [AWS IAM User MFA ](../policies/aws_iam_policies/aws_iam_user_mfa.yml)
- [AWS IAM User Not In Conflicting Groups](../policies/aws_iam_policies/aws_iam_user_not_in_conflicting_groups.yml)
- [AWS Resource Minimum Tags ](../policies/aws_account_policies/aws_resource_minimum_tags.yml)
- [AWS Resource Required Tags](../policies/aws_account_policies/aws_resource_required_tags.yml)
- [AWS Root Account Access Keys](../policies/aws_iam_policies/aws_root_account_access_keys.yml)
- [AWS Root Account Hardware MFA](../policies/aws_iam_policies/aws_root_account_hardware_mfa.yml)
- [AWS Root Account MFA](../policies/aws_iam_policies/aws_root_account_mfa.yml)
- [AWS Unused Access Key](../policies/aws_iam_policies/aws_access_key_unused.yml)
- [IAM Inline Policy Network Admin](../policies/aws_iam_policies/aws_iam_inline_policy_does_not_grant_network_admin_access.yml)


## AWS KMS

- [AWS KMS CMK Key Rotation](../policies/aws_kms_policies/aws_cmk_key_rotation.yml)
- [AWS KMS Key Restricts Usage](../policies/aws_kms_policies/aws_kms_key_policy_restricts_usage.yml)


## AWS PasswordPolicy

- [AWS Password Policy Complexity Guidelines](../policies/aws_account_policies/aws_password_policy_complexity_guidelines.yml)
- [AWS Password Policy Password Age Limit](../policies/aws_account_policies/aws_password_policy_password_age_limit.yml)
- [AWS Password Policy Password Reuse](../policies/aws_account_policies/aws_password_policy_password_reuse.yml)


## AWS RDS

- [AWS RDS Instance Backup](../policies/aws_rds_policies/aws_rds_instance_backup.yml)
- [AWS RDS Instance Encryption](../policies/aws_rds_policies/aws_rds_instance_encryption.yml)
- [AWS RDS Instance Has Acceptable Backup Retention Period](../policies/aws_rds_policies/aws_rds_instance_backup_retention_acceptable.yml)
- [AWS RDS Instance High Availability](../policies/aws_rds_policies/aws_rds_instance_high_availability.yml)
- [AWS RDS Instance Minor Version Upgrades](../policies/aws_rds_policies/aws_rds_instance_auto_minor_version_upgrade_enabled.yml)
- [AWS RDS Instance Public Access](../policies/aws_rds_policies/aws_rds_instance_public_access.yml)
- [AWS RDS Instance Snapshot Public Access](../policies/aws_rds_policies/aws_rds_instance_snapshot_public_access.yml)


## AWS Redshift

- [AWS Redshift Cluster Encryption](../policies/aws_redshift_policies/aws_redshift_cluster_encryption.yml)
- [AWS Redshift Cluster Has Acceptable Snapshot Retention Period](../policies/aws_redshift_policies/aws_redshift_cluster_snapshot_retention_acceptable.yml)
- [AWS Redshift Cluster Logging](../policies/aws_redshift_policies/aws_redshift_cluster_logging.yml)
- [AWS Redshift Cluster Maintenance Window](../policies/aws_redshift_policies/aws_redshift_cluster_maintenance_window.yml)
- [AWS Redshift Cluster Snapshot Retention](../policies/aws_redshift_policies/aws_redshift_cluster_snapshot_retention.yml)
- [AWS Redshift Cluster Version Upgrade](../policies/aws_redshift_policies/aws_redshift_cluster_version_upgrade.yml)


## AWS S3

- [AWS S3 Bucket Action Restrictions](../policies/aws_s3_policies/aws_s3_bucket_action_restrictions.yml)
- [AWS S3 Bucket Encryption](../policies/aws_s3_policies/aws_s3_bucket_encryption.yml)
- [AWS S3 Bucket Lifecycle Configuration](../policies/aws_s3_policies/aws_s3_bucket_lifecycle_configuration.yml)
- [AWS S3 Bucket Logging](../policies/aws_s3_policies/aws_s3_bucket_logging.yml)
- [AWS S3 Bucket MFA Delete](../policies/aws_s3_policies/aws_s3_bucket_mfa_delete.yml)
- [AWS S3 Bucket Name DNS Compliance](../policies/aws_s3_policies/aws_s3_bucket_name_dns_compliance.yml)
- [AWS S3 Bucket Object Lock Configured](../policies/aws_s3_policies/aws_s3_bucket_object_lock_configured.yml)
- [AWS S3 Bucket Policy Allow With Not Principal](../policies/aws_s3_policies/aws_s3_bucket_policy_allow_with_not_principal.yml)
- [AWS S3 Bucket Principal Restrictions](../policies/aws_s3_policies/aws_s3_bucket_principal_restrictions.yml)
- [AWS S3 Bucket Public Access Block](../policies/aws_s3_policies/aws_s3_bucket_public_access_block.yml)
- [AWS S3 Bucket Public Read](../policies/aws_s3_policies/aws_s3_bucket_public_read.yml)
- [AWS S3 Bucket Public Write](../policies/aws_s3_policies/aws_s3_bucket_public_write.yml)
- [AWS S3 Bucket Secure Access](../policies/aws_s3_policies/aws_s3_bucket_secure_access.yml)
- [AWS S3 Bucket Versioning](../policies/aws_s3_policies/aws_s3_bucket_versioning.yml)
- [S3 Bucket Policy Confused Deputy Protection for Service Principals](../policies/aws_s3_policies/aws_s3_bucket_policy_confused_deputy.yml)


## AWS S3ServerAccess

- [AWS S3 Access Error](../rules/aws_s3_rules/aws_s3_access_error.yml)
- [AWS S3 Access IP Allowlist](../rules/aws_s3_rules/aws_s3_access_ip_allowlist.yml)
- [AWS S3 Insecure Access](../rules/aws_s3_rules/aws_s3_insecure_access.yml)
- [AWS S3 Unauthenticated Access](../rules/aws_s3_rules/aws_s3_unauthenticated_access.yml)
- [AWS S3 Unknown Requester](../rules/aws_s3_rules/aws_s3_unknown_requester_get_object.yml)


## AWS SecurityFindingFormat

- [Decoy DynamoDB Accessed](../rules/aws_securityfinding_rules/decoy_dynamodb_accessed.yml)
- [Decoy IAM Assumed](../rules/aws_securityfinding_rules/decoy_iam_assumed.yml)
- [Decoy S3 Accessed](../rules/aws_securityfinding_rules/decoy_s3_accessed.yml)
- [Decoy Secret Accessed](../rules/aws_securityfinding_rules/decoy_secret_accessed.yml)
- [Decoy Systems Manager Parameter Accessed](../rules/aws_securityfinding_rules/decoy_systems_manager_parameter_accessed.yml)


## AWS VPCDns

- [AWS DNS Crypto Domain](../rules/aws_vpc_flow_rules/aws_dns_crypto_domain.yml)
- [DNS Base64 Encoded Query](../rules/standard_rules/standard_dns_base64.yml)
- [VPC DNS Tunneling](../queries/aws_queries/vpc_dns_tunneling.yml)


## AWS VPCFlow

- [AWS VPC Healthy Log Status](../rules/aws_vpc_flow_rules/aws_vpc_healthy_log_status.yml)
- [VPC Flow Logs Inbound Port Allowlist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_allowlist.yml)
- [VPC Flow Logs Inbound Port Blocklist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_blocklist.yml)
- [VPC Flow Logs Unapproved Outbound DNS Traffic](../rules/aws_vpc_flow_rules/aws_vpc_unapproved_outbound_dns.yml)
- [VPC Flow Port Scanning](../queries/aws_queries/anomalous_vpc_port_activity.yml)


## AWS WAF

- [AWS WAF Has XSS Predicate](../policies/aws_waf_policies/aws_waf_has_xss_predicate.yml)
- [AWS WAF Logging Configured](../policies/aws_waf_policies/aws_waf_logging_configured.yml)
- [AWS WAF Rule Ordering](../policies/aws_waf_policies/aws_waf_rule_ordering.yml)
- [AWS WAF WebACL Has Associated Resources](../policies/aws_waf_policies/aws_waf_webacl_has_associated_resources.yml)


## AppOmni

- [AppOmni Alert Passthrough](../rules/appomni_rules/appomni_alert_passthrough.yml)


## Asana

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
- [Asana Service Account Created](../rules/asana_rules/asana_service_account_created.yml)
- [Asana Team Privacy Public](../rules/asana_rules/asana_team_privacy_public.yml)
- [Asana Workspace Default Session Duration Never](../rules/asana_rules/asana_workspace_default_session_duration_never.yml)
- [Asana Workspace Email Domain Added](../rules/asana_rules/asana_workspace_email_domain_added.yml)
- [Asana Workspace Form Link Auth Requirement Disabled](../rules/asana_rules/asana_workspace_form_link_auth_requirement_disabled.yml)
- [Asana Workspace Guest Invite Permissions Anyone](../rules/asana_rules/asana_workspace_guest_invite_permissions_anyone.yml)
- [Asana Workspace New Admin](../rules/asana_rules/asana_workspace_new_admin.yml)
- [Asana Workspace Org Export](../rules/asana_rules/asana_workspace_org_export.yml)
- [Asana Workspace Password Requirements Simple](../rules/asana_rules/asana_workspace_password_requirements_simple.yml)
- [Asana Workspace Require App Approvals Disabled](../rules/asana_rules/asana_workspace_require_app_approvals_disabled.yml)
- [Asana Workspace SAML Optional](../rules/asana_rules/asana_workspace_saml_optional.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)


## Atlassian

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
- [Atlassian admin impersonated another user](../rules/atlassian_rules/user_logged_in_as_user.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)


## Auth0

- [Auth0 CIC Credential Stuffing](../rules/auth0_rules/auth0_cic_credential_stuffing.yml)
- [Auth0 CIC Credential Stuffing Query](../queries/auth0_queries/auth0_cic_credential_stuffing_query.yml)
- [Auth0 Custom Role Created](../rules/auth0_rules/auth0_custom_role_created.yml)
- [Auth0 Integration Installed](../rules/auth0_rules/auth0_integration_installed.yml)
- [Auth0 mfa factor enabled](../rules/auth0_rules/auth0_mfa_factor_setting_enabled.yml)
- [Auth0 MFA Policy Disabled](../rules/auth0_rules/auth0_mfa_policy_disabled.yml)
- [Auth0 MFA Policy Enabled](../rules/auth0_rules/auth0_mfa_policy_enabled.yml)
- [Auth0 MFA Risk Assessment Disabled](../rules/auth0_rules/auth0_mfa_risk_assessment_disabled.yml)
- [Auth0 MFA Risk Assessment Enabled](../rules/auth0_rules/auth0_mfa_risk_assessment_enabled.yml)
- [Auth0 Post Login Action Flow Updated](../rules/auth0_rules/auth0_post_login_action_flow.yml)
- [Auth0 User Invitation Created](../rules/auth0_rules/auth0_user_invitation_created.yml)
- [Auth0 User Joined Tenant](../rules/auth0_rules/auth0_user_joined_tenant.yml)


## Azure

- [Azure Many Failed SignIns](../rules/azure_signin_rules/azure_failed_signins.yml)
- [Azure RiskLevel Passthrough](../rules/azure_signin_rules/azure_risklevel_passthrough.yml)
- [Azure SignIn via Legacy Authentication Protocol](../rules/azure_signin_rules/azure_legacyauth.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)


# B

- [Box](#box)


## Box

- [Box Access Granted](../rules/box_rules/box_access_granted.yml)
- [Box Content Workflow Policy Violation](../rules/box_rules/box_policy_violation.yml)
- [Box event triggered by unknown or external user](../rules/box_rules/box_event_triggered_externally.yml)
- [Box item shared externally](../rules/box_rules/box_item_shared_externally.yml)
- [Box Large Number of Downloads](../rules/box_rules/box_user_downloads.yml)
- [Box Large Number of Permission Changes](../rules/box_rules/box_user_permission_updates.yml)
- [Box New Login](../rules/box_rules/box_new_login.yml)
- [Box Shield Detected Anomalous Download Activity](../rules/box_rules/box_anomalous_download.yml)
- [Box Shield Suspicious Alert Triggered](../rules/box_rules/box_suspicious_login_or_session.yml)
- [Box Untrusted Device Login](../rules/box_rules/box_untrusted_device.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [Malicious Content Detected](../rules/box_rules/box_malicious_content.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)


# C

- [CarbonBlack](#carbonblack)
- [CiscoUmbrella](#ciscoumbrella)
- [Cloudflare](#cloudflare)
- [Crowdstrike](#crowdstrike)


## CarbonBlack

- [Carbon Black Admin Role Granted](../rules/carbonblack_rules/cb_audit_admin_grant.yml)
- [Carbon Black API Key Created or Retrieved](../rules/carbonblack_rules/cb_audit_api_key_created_retrieved.yml)
- [Carbon Black Data Forwarder Stopped](../rules/carbonblack_rules/cb_audit_data_forwarder_stopped.yml)
- [Carbon Black Log Entry Flagged](../rules/carbonblack_rules/cb_audit_flagged.yml)
- [Carbon Black Passthrough Rule](../rules/carbonblack_rules/cb_passthrough.yml)
- [Carbon Black User Added Outside Org](../rules/carbonblack_rules/cb_audit_user_added_outside_org.yml)


## CiscoUmbrella

- [Cisco Umbrella Domain Blocked](../rules/cisco_umbrella_dns_rules/domain_blocked.yml)
- [Cisco Umbrella Domain Name Fuzzy Matching](../rules/cisco_umbrella_dns_rules/fuzzy_matching_domains.yml)
- [Cisco Umbrella Suspicious Domains](../rules/cisco_umbrella_dns_rules/suspicious_domains.yml)
- [DNS Base64 Encoded Query](../rules/standard_rules/standard_dns_base64.yml)
- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)


## Cloudflare

- [Cloudflare Bot High Volume](../rules/cloudflare_rules/cloudflare_httpreq_bot_high_volume.yml)
- [Cloudflare L7 DDoS](../rules/cloudflare_rules/cloudflare_firewall_ddos.yml)


## Crowdstrike

- [1Password Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/onepassword_login_from_crowdstrike_unmanaged_device.yml)
- [1Password Login From CrowdStrike Unmanaged Device Query](../queries/crowdstrike_queries/onepass_login_from_crowdstrike_unmanaged_device_query.yml)
- [1Password Login From CrowdStrike Unmanaged Device Query (crowdstrike_fdrevent table)](../queries/onepassword_queries/onepass_login_from_crowdstrike_unmanaged_device_FDREvent.yml)
- [AWS Authentication From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device.yml)
- [AWS Authentication from CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/aws_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device_FDREvent.yml)
- [Connection to Embargoed Country](../rules/crowdstrike_rules/crowdstrike_connection_to_embargoed_country.yml)
- [Crowdstrike Admin Role Assigned](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_admin_role_assigned.yml)
- [Crowdstrike Allowlist Removed](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_allowlist_removed.yml)
- [Crowdstrike API Key Created](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_api_key_created.yml)
- [Crowdstrike API Key Deleted](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_api_key_deleted.yml)
- [Crowdstrike Credential Dumping Tool](../rules/crowdstrike_rules/crowdstrike_credential_dumping_tool.yml)
- [Crowdstrike Cryptomining Tools ](../rules/crowdstrike_rules/crowdstrike_cryptomining_tools.yml)
- [Crowdstrike Detection Passthrough](../rules/crowdstrike_rules/crowdstrike_detection_passthrough.yml)
- [Crowdstrike Detection Summary](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_detection_summary.yml)
- [Crowdstrike Ephemeral User Account](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_ephemeral_user_account.yml)
- [Crowdstrike FDR LOLBAS](../rules/crowdstrike_rules/crowdstrike_lolbas.yml)
- [Crowdstrike IP Allowlist Changed](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_ip_allowlist_changed.yml)
- [CrowdStrike Large Zip Creation](../queries/crowdstrike_queries/CrowdStrike_Large_Zip_Creation.yml)
- [CrowdStrike Large Zip Creation (crowdstrike_fdrevent table)](../queries/crowdstrike_queries/CrowdStrike_Large_Zip_Creation_FDREvent.yml)
- [CrowdStrike MacOS Added Trusted Cert](../rules/crowdstrike_rules/crowdstrike_macos_add_trusted_cert.yml)
- [CrowdStrike MacOS Osascript as Administrator](../rules/crowdstrike_rules/crowdstrike_macos_osascript_administrator.yml)
- [CrowdStrike MacOS plutil Usage](../rules/crowdstrike_rules/crowdstrike_macos_plutil_usage.yml)
- [Crowdstrike New Admin User Created](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_new_admin_user_created.yml)
- [Crowdstrike New User Created](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_new_user_created.yml)
- [Crowdstrike Real Time Response (RTS) Session](../rules/crowdstrike_rules/crowdstrike_real_time_response_session.yml)
- [Crowdstrike Remote Access Tool Execution](../rules/crowdstrike_rules/crowdstrike_remote_access_tool_execution.yml)
- [Crowdstrike Reverse Shell Tool Executed](../rules/crowdstrike_rules/crowdstrike_reverse_shell_tool_executed.yml)
- [Crowdstrike Single IP Allowlisted](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_single_ip_allowlisted.yml)
- [Crowdstrike Systemlog Tampering](../rules/crowdstrike_rules/crowdstrike_systemlog_tampering.yml)
- [Crowdstrike Unusual Parent Child Processes](../rules/crowdstrike_rules/crowdstrike_unusual_parent_child_processes.yml)
- [Crowdstrike User Deleted](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_user_deleted.yml)
- [Crowdstrike User Password Changed](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_password_change.yml)
- [Crowdstrike WMI Query Detection](../rules/crowdstrike_rules/crowdstrike_wmi_query_detection.yml)
- [DNS Base64 Encoded Query](../rules/standard_rules/standard_dns_base64.yml)
- [DNS request to denylisted domain](../rules/crowdstrike_rules/crowdstrike_dns_request.yml)
- [Execution of Command Line Tool with Base64 Encoded Arguments](../rules/crowdstrike_rules/crowdstrike_base64_encoded_args.yml)
- [MacOS Browser Credential Access (crowdstrike_fdrevent table)](../queries/crowdstrike_queries/MacOS_Browser_Credential_Access_FDREvent.yml)
- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)
- [Okta Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device.yml)
- [Okta Login From CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/okta_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device_FDREvent.yml)


# D

- [Dropbox](#dropbox)
- [Duo](#duo)


## Dropbox

- [Dropbox Admin sign-in-as Session](../rules/dropbox_rules/dropbox_admin_sign_in_as_session.yml)
- [Dropbox Document/Folder Ownership Transfer](../rules/dropbox_rules/dropbox_ownership_transfer.yml)
- [Dropbox External Share](../rules/dropbox_rules/dropbox_external_share.yml)
- [Dropbox Linked Team Application Added](../rules/dropbox_rules/dropbox_linked_team_application_added.yml)
- [Dropbox Many Deletes](../queries/dropbox_queries/Dropbox_Many_Deletes_Query.yml)
- [Dropbox Many Downloads](../queries/dropbox_queries/Dropbox_Many_Downloads.yml)
- [Dropbox User Disabled 2FA](../rules/dropbox_rules/dropbox_user_disabled_2fa.yml)


## Duo

- [Duo Admin App Integration Secret Key Viewed](../rules/duo_rules/duo_admin_app_integration_secret_key_viewed.yml)
- [Duo Admin Bypass Code Created](../rules/duo_rules/duo_admin_bypass_code_created.yml)
- [Duo Admin Bypass Code Viewed](../rules/duo_rules/duo_admin_bypass_code_viewed.yml)
- [Duo Admin Create Admin](../rules/duo_rules/duo_admin_create_admin.yml)
- [Duo Admin Lockout](../rules/duo_rules/duo_admin_lockout.yml)
- [Duo Admin Marked Push Fraudulent](../rules/duo_rules/duo_admin_marked_push_fraudulent.yml)
- [Duo Admin MFA Restrictions Updated](../rules/duo_rules/duo_admin_mfa_restrictions_updated.yml)
- [Duo Admin New Admin API App Integration](../rules/duo_rules/duo_admin_new_admin_api_app_integration.yml)
- [Duo Admin Policy Updated](../rules/duo_rules/duo_admin_policy_updated.yml)
- [Duo Admin SSO SAML Requirement Disabled](../rules/duo_rules/duo_admin_sso_saml_requirement_disabled.yml)
- [Duo Admin User MFA Bypass Enabled](../rules/duo_rules/duo_admin_user_mfa_bypass_enabled.yml)
- [Duo User Action Reported as Fraudulent](../rules/duo_rules/duo_user_action_fraudulent.yml)
- [Duo User Auth Denied For Anomalous Push](../rules/duo_rules/duo_user_anomalous_push.yml)
- [Duo User Bypass Code Used](../rules/duo_rules/duo_user_bypass_code_used.yml)
- [Duo User Denied For Endpoint Error](../rules/duo_rules/duo_user_endpoint_failure_multi.yml)


# G

- [GCP](#gcp)
- [GitHub](#github)
- [GitLab](#gitlab)
- [Google Workspace](#google-workspace)


## GCP

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
- [Exec into Pod](../rules/gcp_k8s_rules/gcp_k8s_exec_into_pod.yml)
- [GCP Access Attempts Violating IAP Access Controls](../rules/gcp_http_lb_rules/gcp_access_attempts_violating_iap_access_controls.yml)
- [GCP Access Attempts Violating VPC Service Controls](../rules/gcp_audit_rules/gcp_access_attempts_violating_vpc_service_controls.yml)
- [GCP BigQuery Large Scan](../rules/gcp_audit_rules/gcp_bigquery_large_scan.yml)
- [GCP Cloud Run Service Created](../rules/gcp_audit_rules/gcp_cloud_run_service_created.yml)
- [GCP Cloud Run Service Created FOLLOWED BY Set IAM Policy](../correlation_rules/gcp_cloud_run_service_create_followed_by_set_iam_policy.yml)
- [GCP Cloud Run Set IAM Policy](../rules/gcp_audit_rules/gcp_cloud_run_set_iam_policy.yml)
- [GCP Cloud Storage Buckets Modified Or Deleted](../rules/gcp_audit_rules/gcp_cloud_storage_buckets_modified_or_deleted.yml)
- [GCP CloudBuild Potential Privilege Escalation](../rules/gcp_audit_rules/gcp_cloudbuild_potential_privilege_escalation.yml)
- [GCP cloudfunctions functions create](../rules/gcp_audit_rules/gcp_cloudfunctions_functions_create.yml)
- [GCP cloudfunctions functions update](../rules/gcp_audit_rules/gcp_cloudfunctions_functions_update.yml)
- [GCP compute.instances.create Privilege Escalation](../rules/gcp_audit_rules/gcp_computeinstances_create_privilege_escalation.yml)
- [GCP Corporate Email Not Used](../rules/gcp_audit_rules/gcp_iam_corp_email.yml)
- [GCP Destructive Queries](../rules/gcp_audit_rules/gcp_destructive_queries.yml)
- [GCP DNS Zone Modified or Deleted](../rules/gcp_audit_rules/gcp_dns_zone_modified_or_deleted.yml)
- [GCP Firewall Rule Created](../rules/gcp_audit_rules/gcp_firewall_rule_created.yml)
- [GCP Firewall Rule Deleted](../rules/gcp_audit_rules/gcp_firewall_rule_deleted.yml)
- [GCP Firewall Rule Modified](../rules/gcp_audit_rules/gcp_firewall_rule_modified.yml)
- [GCP GCS IAM Permission Changes](../rules/gcp_audit_rules/gcp_gcs_iam_changes.yml)
- [GCP GKE Kubernetes Cron Job Created Or Modified](../rules/gcp_k8s_rules/gcp_k8s_cron_job_created_or_modified.yml)
- [GCP IAM Role Has Changed](../rules/gcp_audit_rules/gcp_iam_custom_role_changes.yml)
- [GCP IAM serviceAccounts getAccessToken Privilege Escalation](../rules/gcp_audit_rules/gcp_iam_service_accounts_get_access_token_privilege_escalation.yml)
- [GCP IAM serviceAccounts signBlob](../rules/gcp_audit_rules/gcp_iam_service_accounts_sign_blob.yml)
- [GCP IAM serviceAccounts.signJwt Privilege Escalation](../rules/gcp_audit_rules/gcp_iam_serviceaccounts_signjwt.yml)
- [GCP iam.roles.update Privilege Escalation](../rules/gcp_audit_rules/gcp_iam_roles_update_privilege_escalation.yml)
- [GCP Inbound SSO Profile Created](../rules/gcp_audit_rules/gcp_inbound_sso_profile_created_or_updated.yml)
- [GCP K8s IOCActivity](../rules/gcp_k8s_rules/gcp_k8s_ioc_activity.yml)
- [GCP K8s New Daemonset Deployed](../rules/gcp_k8s_rules/gcp_k8s_new_daemonset_deployed.yml)
- [GCP K8s Pod Attached To Node Host Network](../rules/gcp_k8s_rules/gcp_k8s_pod_attached_to_node_host_network.yml)
- [GCP K8S Pod Create Or Modify Host Path Volume Mount](../rules/gcp_k8s_rules/gcp_k8s_pod_create_or_modify_host_path_vol_mount.yml)
- [GCP K8s Pod Using Host PID Namespace](../rules/gcp_k8s_rules/gcp_k8s_pod_using_host_pid_namespace.yml)
- [GCP K8S Privileged Pod Created](../rules/gcp_k8s_rules/gcp_k8s_privileged_pod_created.yml)
- [GCP K8S Service Type NodePort Deployed](../rules/gcp_k8s_rules/gcp_k8s_service_type_node_port_deployed.yml)
- [GCP Log Bucket or Sink Deleted](../rules/gcp_audit_rules/gcp_log_bucket_or_sink_deleted.yml)
- [GCP Logging Settings Modified](../rules/gcp_audit_rules/gcp_logging_settings_modified.yml)
- [GCP Logging Sink Modified](../rules/gcp_audit_rules/gcp_logging_sink_modified.yml)
- [GCP Org or Folder Policy Was Changed Manually](../rules/gcp_audit_rules/gcp_iam_org_folder_changes.yml)
- [GCP Permissions Granted to Create or Manage Service Account Key](../rules/gcp_audit_rules/gcp_permissions_granted_to_create_or_manage_service_account_key.yml)
- [GCP Resource in Unused Region](../rules/gcp_audit_rules/gcp_unused_regions.yml)
- [GCP Service Account Access Denied](../rules/gcp_audit_rules/gcp_service_account_access_denied.yml)
- [GCP Service Account or Keys Created ](../rules/gcp_audit_rules/gcp_service_account_or_keys_created.yml)
- [GCP serviceusage.apiKeys.create Privilege Escalation](../rules/gcp_audit_rules/gcp_serviceusage_apikeys_create_privilege_escalation.yml)
- [GCP SQL Config Changes](../rules/gcp_audit_rules/gcp_sql_config_changes.yml)
- [GCP storage hmac keys create](../rules/gcp_audit_rules/gcp_storage_hmac_keys_create.yml)
- [GCP User Added to IAP Protected Service](../rules/gcp_audit_rules/gcp_user_added_to_iap_protected_service.yml)
- [GCP User Added to Privileged Group](../rules/gcp_audit_rules/gcp_user_added_to_privileged_group.yml)
- [GCP VPC Flow Logs Disabled](../rules/gcp_audit_rules/gcp_vpc_flow_logs_disabled.yml)
- [GCP Workforce Pool Created or Updated](../rules/gcp_audit_rules/gcp_workforce_pool_created_or_updated.yml)
- [GCP Workload Identity Pool Created or Updated](../rules/gcp_audit_rules/gcp_workload_identity_pool_created_or_updated.yml)
- [GCP.Iam.ServiceAccountKeys.Create](../rules/gcp_audit_rules/gcp_iam_service_account_key_create.yml)
- [GCP.Privilege.Escalation.By.Deployments.Create](../rules/gcp_audit_rules/gcp_privilege_escalation_by_deployments_create.yml)
- [GCS Bucket Made Public](../rules/gcp_audit_rules/gcp_gcs_public.yml)


## GitHub

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
- [GitHub Action Failed](../rules/github_rules/github_action_failed.yml)
- [GitHub Advanced Security Change WITHOUT Repo Archived](../correlation_rules/github_advanced_security_change_not_followed_by_repo_archived.yml)
- [GitHub Branch Protection Disabled](../rules/github_rules/github_branch_protection_disabled.yml)
- [GitHub Branch Protection Policy Override](../rules/github_rules/github_branch_policy_override.yml)
- [GitHub Dependabot Vulnerability Dismissed](../rules/github_rules/github_repo_vulnerability_dismissed.yml)
- [GitHub Org Authentication Method Changed](../rules/github_rules/github_org_auth_modified.yml)
- [GitHub Org IP Allow List modified](../rules/github_rules/github_org_ip_allowlist.yml)
- [Github Organization App Integration Installed](../rules/github_rules/github_organization_app_integration_installed.yml)
- [Github Public Repository Created](../rules/github_rules/github_public_repository_created.yml)
- [GitHub Repository Archived](../rules/github_rules/github_repo_archived.yml)
- [GitHub Repository Collaborator Change](../rules/github_rules/github_repo_collaborator_change.yml)
- [GitHub Repository Created](../rules/github_rules/github_repo_created.yml)
- [Github Repository Transfer](../rules/github_rules/github_repository_transfer.yml)
- [GitHub Repository Visibility Change](../rules/github_rules/github_repo_visibility_change.yml)
- [GitHub Secret Scanning Alert Created](../rules/github_rules/github_secret_scanning_alert_created.yml)
- [GitHub Security Change, includes GitHub Advanced Security](../rules/github_rules/github_advanced_security_change.yml)
- [GitHub Team Modified](../rules/github_rules/github_team_modified.yml)
- [GitHub User Access Key Created](../rules/github_rules/github_user_access_key_created.yml)
- [GitHub User Added or Removed from Org](../rules/github_rules/github_org_modified.yml)
- [GitHub User Added to Org Moderators](../rules/github_rules/github_org_moderators_add.yml)
- [GitHub User Initial Access to Private Repo](../rules/github_rules/github_repo_initial_access.yml)
- [GitHub User Role Updated](../rules/github_rules/github_user_role_updated.yml)
- [GitHub Web Hook Modified](../rules/github_rules/github_webhook_modified.yml)
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
- [Secret Exposed and not Quarantined](../correlation_rules/secret_exposed_and_not_quarantined.yml)


## GitLab

- [CVE-2023-7028 - GitLab Audit Password Reset Multiple Emails](../rules/gitlab_rules/gitlab_audit_password_reset_multiple_emails.yml)
- [CVE-2023-7028 - GitLab Production Password Reset Multiple Emails](../rules/gitlab_rules/gitlab_production_password_reset_multiple_emails.yml)


## Google Workspace

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [External GSuite File Share](../rules/gsuite_reports_rules/gsuite_drive_external_share.yml)
- [Google Accessed a GSuite Resource](../rules/gsuite_activityevent_rules/gsuite_google_access.yml)
- [Google Drive High Download Count](../queries/gsuite_queries/gsuite_drive_many_docs_downloaded.yml)
- [Google Workspace Admin Custom Role](../rules/gsuite_activityevent_rules/google_workspace_admin_custom_role.yml)
- [Google Workspace Advanced Protection Program](../rules/gsuite_activityevent_rules/google_workspace_advanced_protection_program.yml)
- [Google Workspace Apps Marketplace Allowlist](../rules/gsuite_activityevent_rules/google_workspace_apps_marketplace_allowlist.yml)
- [Google Workspace Apps Marketplace New Domain Application](../rules/gsuite_activityevent_rules/google_workspace_apps_marketplace_new_domain_application.yml)
- [Google Workspace Apps New Mobile App Installed](../rules/gsuite_activityevent_rules/google_workspace_apps_new_mobile_app_installed.yml)
- [GSuite Calendar Has Been Made Public](../rules/gsuite_activityevent_rules/gsuite_calendar_made_public.yml)
- [GSuite Device Suspicious Activity](../rules/gsuite_activityevent_rules/gsuite_mobile_device_suspicious_activity.yml)
- [GSuite Document External Ownership Transfer](../rules/gsuite_activityevent_rules/gsuite_doc_ownership_transfer.yml)
- [GSuite Drive Many Documents Deleted](../queries/gsuite_queries/gsuite_drive_many_docs_deleted.yml)
- [GSuite External Drive Document](../rules/gsuite_reports_rules/gsuite_drive_visibility_change.yml)
- [GSuite Government Backed Attack](../rules/gsuite_activityevent_rules/gsuite_gov_attack.yml)
- [GSuite Login Type](../rules/gsuite_activityevent_rules/gsuite_login_type.yml)
- [Gsuite Mail forwarded to external domain](../rules/gsuite_activityevent_rules/gsuite_external_forwarding.yml)
- [GSuite Many Docs Deleted Query](../queries/gsuite_queries/GSuite_Many_Docs_Deleted_Query.yml)
- [GSuite Many Docs Downloaded Query](../queries/gsuite_queries/GSuite_Many_Docs_Downloaded_Query.yml)
- [GSuite Overly Visible Drive Document](../rules/gsuite_reports_rules/gsuite_drive_overly_visible.yml)
- [GSuite Passthrough Rule Triggered](../rules/gsuite_activityevent_rules/gsuite_passthrough_rule.yml)
- [GSuite User Advanced Protection Change](../rules/gsuite_activityevent_rules/gsuite_advanced_protection.yml)
- [GSuite User Banned from Group](../rules/gsuite_activityevent_rules/gsuite_group_banned_user.yml)
- [GSuite User Device Compromised](../rules/gsuite_activityevent_rules/gsuite_mobile_device_compromise.yml)
- [GSuite User Device Unlock Failures](../rules/gsuite_activityevent_rules/gsuite_mobile_device_screen_unlock_fail.yml)
- [GSuite User Password Leaked](../rules/gsuite_activityevent_rules/gsuite_leaked_password.yml)
- [GSuite User Suspended](../rules/gsuite_activityevent_rules/gsuite_user_suspended.yml)
- [GSuite User Two Step Verification Change](../rules/gsuite_activityevent_rules/gsuite_two_step_verification.yml)
- [GSuite Workspace Calendar External Sharing Setting Change](../rules/gsuite_activityevent_rules/gsuite_workspace_calendar_external_sharing.yml)
- [GSuite Workspace Data Export Has Been Created](../rules/gsuite_activityevent_rules/gsuite_workspace_data_export_created.yml)
- [GSuite Workspace Gmail Default Routing Rule Modified](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_default_routing_rule.yml)
- [GSuite Workspace Gmail Pre-Delivery Message Scanning Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_enhanced_predelivery_scanning.yml)
- [GSuite Workspace Gmail Security Sandbox Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_security_sandbox_disabled.yml)
- [GSuite Workspace Password Reuse Has Been Enabled](../rules/gsuite_activityevent_rules/gsuite_workspace_password_reuse_enabled.yml)
- [GSuite Workspace Strong Password Enforcement Has Been Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_password_enforce_strong_disabled.yml)
- [GSuite Workspace Trusted Domain Allowlist Modified](../rules/gsuite_activityevent_rules/gsuite_workspace_trusted_domains_allowlist.yml)
- [Suspicious GSuite Login](../rules/gsuite_activityevent_rules/gsuite_suspicious_logins.yml)


# M

- [Microsoft365](#microsoft365)
- [MicrosoftGraph](#microsoftgraph)
- [MongoDB](#mongodb)


## Microsoft365

- [Microsoft Exchange External Forwarding](../rules/microsoft_rules/microsoft_exchange_external_forwarding.yml)
- [Microsoft365 Brute Force Login by User](../rules/microsoft_rules/microsoft365_brute_force_login_by_user.yml)
- [Microsoft365 External Document Sharing](../rules/microsoft_rules/microsoft365_external_sharing.yml)
- [Microsoft365 MFA Disabled](../rules/microsoft_rules/microsoft365_mfa_disabled.yml)


## MicrosoftGraph

- [Microsoft Graph Passthrough](../rules/microsoft_rules/microsoft_graph_passthrough.yml)


## MongoDB

- [MongoDB 2FA Disabled](../rules/mongodb_rules/mongodb_2fa_disabled.yml)
- [MongoDB access allowed from anywhere](../rules/mongodb_rules/mongodb_access_allowed_from_anywhere.yml)
- [MongoDB Atlas API Key Created](../rules/mongodb_rules/mongodb_atlas_api_key_created.yml)
- [MongoDB External User Invited](../rules/mongodb_rules/mongodb_external_user_invited.yml)
- [MongoDB External User Invited (no config)](../rules/mongodb_rules/mongodb_external_user_invited_no_config.yml)
- [MongoDB Identity Provider Activity](../rules/mongodb_rules/mongodb_identity_provider_activity.yml)
- [MongoDB logging toggled](../rules/mongodb_rules/mongodb_logging_toggled.yml)
- [MongoDB org membership restriction disabled](../rules/mongodb_rules/mongodb_org_membership_restriction_disabled.yml)
- [MongoDB security alerts disabled or deleted](../rules/mongodb_rules/mongodb_alerting_disabled.yml)
- [MongoDB user roles changed](../rules/mongodb_rules/mongodb_user_roles_changed.yml)
- [MongoDB user was created or deleted](../rules/mongodb_rules/mongodb_user_created_or_deleted.yml)


# N

- [Netskope](#netskope)
- [Notion](#notion)


## Netskope

- [Action Performed by Netskope Personnel](../rules/netskope_rules/netskope_personnel_action.yml)
- [Admin logged out because of successive login failures](../rules/netskope_rules/netskope_admin_logged_out.yml)
- [An administrator account was created, deleted, or modified.](../rules/netskope_rules/netskope_admin_user_change.yml)
- [Netskope Many Objects Deleted](../rules/netskope_rules/netskope_many_deletes.yml)
- [Netskope Many Unauthorized API Calls](../rules/netskope_rules/netskope_unauthorized_api_calls.yml)


## Notion

- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
- [Notion Audit Log Exported](../rules/notion_rules/notion_workspace_audit_log_exported.yml)
- [Notion Login FOLLOWED BY AccountChange](../correlation_rules/notion_login_followed_by_account_change.yml)
- [Notion Login From Blocked IP](../rules/notion_rules/notion_login_from_blocked_ip.yml)
- [Notion Login from New Location](../rules/notion_rules/notion_login_from_new_location.yml)
- [Notion Many Pages Deleted](../queries/notion_queries/notion_many_pages_deleted_sched.yml)
- [Notion Many Pages Deleted Query](../queries/notion_queries/notion_many_pages_deleted_query.yml)
- [Notion Many Pages Exported](../rules/notion_rules/notion_many_pages_exported.yml)
- [Notion Page API Permissions Changed](../rules/notion_rules/notion_page_accessible_to_api.yml)
- [Notion Page Guest Permissions Changed](../rules/notion_rules/notion_page_accessible_to_guests.yml)
- [Notion Page Published to Web](../rules/notion_rules/notion_page_shared_to_web.yml)
- [Notion SAML SSO Configuration Changed](../rules/notion_rules/notion_workspace_settings_enforce_saml_sso_config_updated.yml)
- [Notion SCIM Token Generated](../rules/notion_rules/notion_scim_token_generated.yml)
- [Notion Sharing Settings Updated](../rules/notion_rules/notion_sharing_settings_updated.yml)
- [Notion Teamspace Owner Added](../rules/notion_rules/notion_teamspace_owner_added.yml)
- [Notion Workspace Exported](../rules/notion_rules/notion_workspace_exported.yml)
- [Notion Workspace public page added](../rules/notion_rules/notion_workspace_settings_public_homepage_added.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)


# O

- [OCSF](#ocsf)
- [Okta](#okta)
- [OneLogin](#onelogin)
- [OnePassword](#onepassword)
- [Osquery](#osquery)


## OCSF

- [AWS DNS Crypto Domain](../rules/aws_vpc_flow_rules/aws_dns_crypto_domain.yml)
- [AWS VPC Healthy Log Status](../rules/aws_vpc_flow_rules/aws_vpc_healthy_log_status.yml)
- [VPC Flow Logs Inbound Port Allowlist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_allowlist.yml)
- [VPC Flow Logs Inbound Port Blocklist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_blocklist.yml)
- [VPC Flow Logs Unapproved Outbound DNS Traffic](../rules/aws_vpc_flow_rules/aws_vpc_unapproved_outbound_dns.yml)


## Okta

- [AWS Console Sign-In NOT PRECEDED BY Okta Redirect](../correlation_rules/aws_console_sign-in_without_okta.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
- [Okta Admin Access Granted](../queries/okta_queries/okta_admin_access_granted.yml)
- [Okta Admin Role Assigned](../rules/okta_rules/okta_admin_role_assigned.yml)
- [Okta AiTM Phishing Attempt Blocked by FastPass](../rules/okta_rules/okta_phishing_attempt_blocked_by_fastpass.yml)
- [Okta API Key Created](../rules/okta_rules/okta_api_key_created.yml)
- [Okta API Key Revoked](../rules/okta_rules/okta_api_key_revoked.yml)
- [Okta App Refresh Access Token Reuse](../rules/okta_rules/okta_app_refresh_access_token_reuse.yml)
- [Okta App Unauthorized Access Attempt](../rules/okta_rules/okta_app_unauthorized_access_attempt.yml)
- [Okta Cleartext Passwords Extracted via SCIM Application](../rules/okta_rules/okta_password_extraction_via_scim.yml)
- [Okta Group Admin Role Assigned](../rules/okta_rules/okta_group_admin_role_assigned.yml)
- [Okta HAR File IOCs](../queries/okta_queries/okta_harfile_iocs.yml)
- [Okta Identity Provider Created or Modified](../rules/okta_rules/okta_idp_create_modify.yml)
- [Okta Identity Provider Sign-in](../rules/okta_rules/okta_idp_signin.yml)
- [Okta Investigate MFA and Password resets](../queries/okta_queries/okta_mfa_password_reset_audit.yml)
- [Okta Investigate Session ID Activity](../queries/okta_queries/okta_session_id_audit.yml)
- [Okta Investigate User Activity](../queries/okta_queries/okta_activity_audit.yml)
- [Okta Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device.yml)
- [Okta Login From CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/okta_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device_FDREvent.yml)
- [Okta MFA Globally Disabled](../rules/okta_rules/okta_admin_disabled_mfa.yml)
- [Okta New Behaviors Acessing Admin Console](../rules/okta_rules/okta_new_behavior_accessing_admin_console.yml)
- [Okta Org2Org application created of modified](../rules/okta_rules/okta_org2org_creation_modification.yml)
- [Okta Password Accessed](../rules/okta_rules/okta_password_accessed.yml)
- [Okta Potentially Stolen Session](../rules/okta_rules/okta_potentially_stolen_session.yml)
- [Okta Rate Limits](../rules/okta_rules/okta_rate_limits.yml)
- [Okta Sign-In from VPN Anonymizer](../rules/okta_rules/okta_anonymizing_vpn_login.yml)
- [Okta Support Access](../queries/okta_queries/okta_support_access.yml)
- [Okta Support Access Granted](../rules/okta_rules/okta_account_support_access.yml)
- [Okta Support Reset Credential](../rules/okta_rules/okta_support_reset.yml)
- [Okta ThreatInsight Security Threat Detected](../rules/okta_rules/okta_threatinsight_security_threat_detected.yml)
- [Okta User Account Locked](../rules/okta_rules/okta_user_account_locked.yml)
- [Okta User MFA Factor Suspend](../rules/okta_rules/okta_user_mfa_factor_suspend.yml)
- [Okta User MFA Own Reset](../rules/okta_rules/okta_user_mfa_reset.yml)
- [Okta User MFA Reset All](../rules/okta_rules/okta_user_mfa_reset_all.yml)
- [Okta User Reported Suspicious Activity](../rules/okta_rules/okta_user_reported_suspicious_activity.yml)
- [Okta Username Above 52 Characters Security Advisory](../queries/okta_queries/okta_52_char_username_threat_hunt.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)


## OneLogin

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
- [OneLogin Active Login Activity](../rules/onelogin_rules/onelogin_active_login_activity.yml)
- [OneLogin Authentication Factor Removed](../rules/onelogin_rules/onelogin_remove_authentication_factor.yml)
- [OneLogin Multiple Accounts Deleted](../rules/onelogin_rules/onelogin_threshold_accounts_deleted.yml)
- [OneLogin Multiple Accounts Modified](../rules/onelogin_rules/onelogin_threshold_accounts_modified.yml)
- [OneLogin Password Access](../rules/onelogin_rules/onelogin_password_accessed.yml)
- [OneLogin Unauthorized Access](../rules/onelogin_rules/onelogin_unauthorized_access.yml)
- [OneLogin User Assumed Another User](../rules/onelogin_rules/onelogin_user_assumed.yml)
- [OneLogin User Locked](../rules/onelogin_rules/onelogin_user_account_locked.yml)
- [OneLogin User Password Changed](../rules/onelogin_rules/onelogin_password_changed.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)


## OnePassword

- [1Password Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/onepassword_login_from_crowdstrike_unmanaged_device.yml)
- [1Password Login From CrowdStrike Unmanaged Device Query](../queries/crowdstrike_queries/onepass_login_from_crowdstrike_unmanaged_device_query.yml)
- [1Password Login From CrowdStrike Unmanaged Device Query (crowdstrike_fdrevent table)](../queries/onepassword_queries/onepass_login_from_crowdstrike_unmanaged_device_FDREvent.yml)
- [BETA - Sensitive 1Password Item Accessed](../rules/onepassword_rules/onepassword_lut_sensitive_item_access.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
- [Configuration Required - Sensitive 1Password Item Accessed](../rules/onepassword_rules/onepassword_sensitive_item_access.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
- [Unusual 1Password Client Detected](../rules/onepassword_rules/onepassword_unusual_client.yml)


## Osquery

- [A backdoored version of XZ or liblzma is vulnerable to CVE-2024-3094](../rules/osquery_rules/osquery_linux_mac_vulnerable_xz_liblzma.yml)
- [A Login from Outside the Corporate Office](../rules/osquery_rules/osquery_linux_logins_non_office.yml)
- [AWS command executed on the command line](../rules/osquery_rules/osquery_linux_aws_commands.yml)
- [MacOS ALF is misconfigured](../rules/osquery_rules/osquery_mac_application_firewall.yml)
- [MacOS Keyboard Events](../rules/osquery_rules/osquery_mac_osx_attacks_keyboard_events.yml)
- [macOS Malware Detected with osquery](../rules/osquery_rules/osquery_mac_osx_attacks.yml)
- [Osquery Agent Outdated](../rules/osquery_rules/osquery_outdated.yml)
- [OSQuery Detected SSH Listener](../rules/osquery_rules/osquery_ssh_listener.yml)
- [OSQuery Detected Unwanted Chrome Extensions](../rules/osquery_rules/osquery_mac_unwanted_chrome_extensions.yml)
- [OSQuery Reports Application Firewall Disabled](../rules/osquery_rules/osquery_mac_enable_auto_update.yml)
- [OSSEC Rootkit Detected via Osquery](../rules/osquery_rules/osquery_ossec.yml)
- [Suspicious cron detected](../rules/osquery_rules/osquery_suspicious_cron.yml)
- [Unsupported macOS version](../rules/osquery_rules/osquery_outdated_macos.yml)


# P

- [Panther](#panther)
- [PushSecurity](#pushsecurity)


## Panther

- [A User Role with Sensitive Permissions has been Created](../rules/panther_audit_rules/panther_sensitive_role_created.yml)
- [A User's Panther Account was Modified](../rules/panther_audit_rules/panther_user_modified.yml)
- [Detection content has been deleted from Panther](../rules/panther_audit_rules/panther_detection_deleted.yml)
- [Panther SAML configuration has been modified](../rules/panther_audit_rules/panther_saml_modified.yml)
- [Snowflake User Daily Query Volume Spike - Threat Hunting](../queries/snowflake_queries/snowflake_user_query_volume_spike_threat_hunting.yml)


## PushSecurity

- [Push Security App Banner Acknowledged](../rules/push_security_rules/push_security_app_banner_acknowledged.yml)
- [Push Security Authorized IdP Login](../rules/push_security_rules/push_security_authorized_idp_login.yml)
- [Push Security New App Detected](../rules/push_security_rules/push_security_new_app_detected.yml)
- [Push Security New SaaS Account Created](../rules/push_security_rules/push_security_new_saas_account_created.yml)
- [Push Security Open Security Finding](../rules/push_security_rules/push_security_open_security_finding.yml)
- [Push Security Phishable MFA Method](../rules/push_security_rules/push_security_phishable_mfa_method.yml)
- [Push Security Phishing Attack](../rules/push_security_rules/push_security_phishing_attack.yml)
- [Push Security SaaS App MFA Method Changed](../rules/push_security_rules/push_security_mfa_method_changed.yml)
- [Push Security Unauthorized IdP Login](../rules/push_security_rules/push_security_unauthorized_idp_login.yml)


# S

- [Salesforce](#salesforce)
- [SentinelOne](#sentinelone)
- [Slack](#slack)
- [Snowflake](#snowflake)
- [Snyk](#snyk)
- [Sublime](#sublime)
- [Suricata](#suricata)


## Salesforce

- [Salesforce Admin Login As User](../rules/salesforce_rules/salesforce_admin_login_as_user.yml)


## SentinelOne

- [SentinelOne Alert Passthrough](../rules/sentinelone_rules/sentinelone_alert_passthrough.yml)
- [SentinelOne Threats](../rules/sentinelone_rules/sentinelone_threats.yml)


## Slack

- [Slack Anomaly Detected](../rules/slack_rules/slack_passthrough_anomaly.yml)
- [Slack App Access Expanded](../rules/slack_rules/slack_app_access_expanded.yml)
- [Slack App Added](../rules/slack_rules/slack_app_added.yml)
- [Slack App Removed](../rules/slack_rules/slack_app_removed.yml)
- [Slack Denial of Service](../rules/slack_rules/slack_application_dos.yml)
- [Slack DLP Modified](../rules/slack_rules/slack_dlp_modified.yml)
- [Slack EKM Config Changed](../rules/slack_rules/slack_ekm_config_changed.yml)
- [Slack EKM Slackbot Unenrolled](../rules/slack_rules/slack_ekm_slackbot_unenrolled.yml)
- [Slack EKM Unenrolled](../rules/slack_rules/slack_ekm_unenrolled.yml)
- [Slack IDP Configuration Changed](../rules/slack_rules/slack_idp_configuration_change.yml)
- [Slack Information Barrier Modified](../rules/slack_rules/slack_information_barrier_modified.yml)
- [Slack Intune MDM Disabled](../rules/slack_rules/slack_intune_mdm_disabled.yml)
- [Slack Legal Hold Policy Modified](../rules/slack_rules/slack_legal_hold_policy_modified.yml)
- [Slack MFA Settings Changed](../rules/slack_rules/slack_mfa_settings_changed.yml)
- [Slack Organization Created](../rules/slack_rules/slack_org_created.yml)
- [Slack Organization Deleted](../rules/slack_rules/slack_org_deleted.yml)
- [Slack Potentially Malicious File Shared](../rules/slack_rules/slack_potentially_malicious_file_shared.yml)
- [Slack Private Channel Made Public](../rules/slack_rules/slack_private_channel_made_public.yml)
- [Slack Service Owner Transferred](../rules/slack_rules/slack_service_owner_transferred.yml)
- [Slack SSO Settings Changed](../rules/slack_rules/slack_sso_settings_changed.yml)
- [Slack User Privilege Escalation](../rules/slack_rules/slack_user_privilege_escalation.yml)
- [Slack User Privileges Changed to User](../rules/slack_rules/slack_privilege_changed_to_user.yml)


## Snowflake

- [Snowflake Account Admin Granted](../queries/snowflake_queries/snowflake_account_admin_assigned.yml)
- [Snowflake Brute Force Attacks by IP](../queries/snowflake_queries/snowflake_brute_force_ip.yml)
- [Snowflake Brute Force Attacks by User](../rules/snowflake_rules/snowflake_stream_brute_force_by_username.yml)
- [Snowflake Brute Force Attacks by Username](../queries/snowflake_queries/snowflake_brute_force_username.yml)
- [Snowflake Brute Force Login Success](../correlation_rules/snowflake_potential_brute_force_success.yml)
- [Snowflake Client IP](../queries/snowflake_queries/snowflake_0108977_ip.yml)
- [Snowflake Configuration Drift](../queries/snowflake_queries/snowflake_0108977_configuration_drift.yml)
- [Snowflake Data Exfiltration](../correlation_rules/snowflake_data_exfiltration.yml)
- [Snowflake External Data Share](../rules/snowflake_rules/snowflake_stream_external_shares.yml)
- [Snowflake External Share](../queries/snowflake_queries/snowflake_external_shares.yml)
- [Snowflake File Downloaded](../queries/snowflake_queries/snowflake_file_downloaded_signal.yml)
- [Snowflake Grant to Public Role](../rules/snowflake_rules/snowflake_stream_public_role_grant.yml)
- [Snowflake Login Without MFA](../queries/snowflake_queries/snowflake_login_without_mfa.yml)
- [Snowflake Multiple Failed Logins Followed By Success](../queries/snowflake_queries/snowflake_multiple_failed_logins_followed_by_success.yml)
- [Snowflake Successful Login](../rules/snowflake_rules/snowflake_stream_login_success.yml)
- [Snowflake Table Copied Into Stage](../queries/snowflake_queries/snowflake_table_copied_into_stage_signal.yml)
- [Snowflake Temporary Stage Created](../queries/snowflake_queries/snowflake_temp_stage_created_signal.yml)
- [Snowflake User Access](../queries/snowflake_queries/snowflake_0109877_suspected_user_access.yml)
- [Snowflake User Created](../queries/snowflake_queries/snowflake_user_created.yml)
- [Snowflake User Daily Query Volume Spike](../queries/snowflake_queries/snowflake_user_query_volume_spike_query.yml)
- [Snowflake User Daily Query Volume Spike - Threat Hunting](../queries/snowflake_queries/snowflake_user_query_volume_spike_threat_hunting.yml)
- [Snowflake User Enabled](../queries/snowflake_queries/snowflake_user_enabled.yml)
- [Snowflake user with key-based auth logged in with password auth](../queries/snowflake_queries/snowflake_key_user_password_login.yml)


## Snyk

- [Snyk Miscellaneous Settings](../rules/snyk_rules/snyk_misc_settings.yml)
- [Snyk Org or Group Settings Change](../rules/snyk_rules/snyk_ou_change.yml)
- [Snyk Org Settings](../rules/snyk_rules/snyk_org_settings.yml)
- [Snyk Project Settings](../rules/snyk_rules/snyk_project_settings.yml)
- [Snyk Role Change](../rules/snyk_rules/snyk_role_change.yml)
- [Snyk Service Account Change](../rules/snyk_rules/snyk_svcacct_change.yml)
- [Snyk System External Access Settings Changed](../rules/snyk_rules/snyk_system_externalaccess.yml)
- [Snyk System Policy Settings Changed](../rules/snyk_rules/snyk_system_policysetting.yml)
- [Snyk System SSO Settings Changed](../rules/snyk_rules/snyk_system_sso.yml)
- [Snyk User Management](../rules/snyk_rules/snyk_user_mgmt.yml)


## Sublime

- [Sublime Flagged an Email](../rules/sublime_rules/sublime_message_flagged.yml)
- [Sublime Mailbox Deactivated](../rules/sublime_rules/sublime_mailboxes_deactivated.yml)
- [Sublime Message Source Deleted Or Deactivated](../rules/sublime_rules/sublime_message_source_deleted_or_deactivated.yml)
- [Sublime Rules Deleted Or Deactivated](../rules/sublime_rules/sublime_rules_deleted_or_deactivated.yml)


## Suricata

- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)


# T

- [Tailscale](#tailscale)
- [Teleport](#teleport)
- [ThinkstCanary](#thinkstcanary)
- [Tines](#tines)


## Tailscale

- [Tailscale HTTPS Disabled](../rules/tailscale_rules/tailscale_https_disabled.yml)
- [Tailscale Machine Approval Requirements Disabled](../rules/tailscale_rules/tailscale_machine_approval_requirements_disabled.yml)
- [Tailscale Magic DNS Disabled](../rules/tailscale_rules/tailscale_magicdns_disabled.yml)


## Teleport

- [A long-lived cert was created](../rules/gravitational_teleport_rules/teleport_long_lived_certs.yml)
- [A SAML Connector was created or modified](../rules/gravitational_teleport_rules/teleport_saml_created.yml)
- [A Teleport Lock was created](../rules/gravitational_teleport_rules/teleport_lock_created.yml)
- [A Teleport Role was modified or created](../rules/gravitational_teleport_rules/teleport_role_created.yml)
- [A user authenticated with SAML, but from an unknown company domain](../rules/gravitational_teleport_rules/teleport_saml_login_not_company_domain.yml)
- [A User from the company domain(s) Logged in without SAML](../rules/gravitational_teleport_rules/teleport_company_domain_login_without_saml.yml)
- [Teleport Create User Accounts](../rules/gravitational_teleport_rules/teleport_create_user_accounts.yml)
- [Teleport Network Scan Initiated](../rules/gravitational_teleport_rules/teleport_network_scanning.yml)
- [Teleport Scheduled Jobs](../rules/gravitational_teleport_rules/teleport_scheduled_jobs.yml)
- [Teleport SSH Auth Errors](../rules/gravitational_teleport_rules/teleport_auth_errors.yml)
- [Teleport Suspicious Commands Executed](../rules/gravitational_teleport_rules/teleport_suspicious_commands.yml)
- [User Logged in as root](../rules/gravitational_teleport_rules/teleport_root_login.yml)
- [User Logged in wihout MFA](../rules/gravitational_teleport_rules/teleport_local_user_login_without_mfa.yml)


## ThinkstCanary

- [Thinkst Canary DCRC](../rules/thinkstcanary_rules/thinkst_canary_dcrc.yml)
- [Thinkst Canary Incident](../rules/thinkstcanary_rules/thinkst_canary_incident.yml)
- [Thinkst Canarytoken Incident](../rules/thinkstcanary_rules/thinkst_canarytoken_incident.yml)


## Tines

- [Tines Actions Disabled Change](../rules/tines_rules/tines_actions_disabled_changes.yml)
- [Tines Custom CertificateAuthority setting changed](../rules/tines_rules/tines_custom_ca.yml)
- [Tines Enqueued/Retrying Job Deletion](../rules/tines_rules/tines_enqueued_retrying_job_deletion.yml)
- [Tines Global Resource Destruction](../rules/tines_rules/tines_global_resource_destruction.yml)
- [Tines SSO Settings](../rules/tines_rules/tines_sso_settings.yml)
- [Tines Story Items Destruction](../rules/tines_rules/tines_story_items_destruction.yml)
- [Tines Story Jobs Clearance](../rules/tines_rules/tines_story_jobs_clearance.yml)
- [Tines Team Destruction](../rules/tines_rules/tines_team_destruction.yml)
- [Tines Tenant API Keys Added](../rules/tines_rules/tines_tenant_authtoken.yml)


# W

- [Wiz](#wiz)


## Wiz

- [Wiz Alert Passthrough Rule](../rules/wiz_rules/wiz_alert_passthrough.yml)
- [Wiz CICD Scan Policy Updated Or Deleted](../rules/wiz_rules/wiz_cicd_scan_policy_updated_or_deleted.yml)
- [Wiz Connector Updated Or Deleted](../rules/wiz_rules/wiz_connector_updated_or_deleted.yml)
- [Wiz Data Classifier Updated Or Deleted](../rules/wiz_rules/wiz_data_classifier_updated_or_deleted.yml)
- [Wiz Image Integrity Validator Updated Or Deleted](../rules/wiz_rules/wiz_image_integrity_validator_updated_or_deleted.yml)
- [Wiz Integration Updated Or Deleted](../rules/wiz_rules/wiz_integration_updated_or_deleted.yml)
- [Wiz Revoke User Sessions](../rules/wiz_rules/wiz_revoke_user_sessions.yml)
- [Wiz Rotate Service Account Secret](../rules/wiz_rules/wiz_rotate_service_account_secret.yml)
- [Wiz Rule Change](../rules/wiz_rules/wiz_rule_change.yml)
- [Wiz SAML Identity Provider Change](../rules/wiz_rules/wiz_saml_identity_provider_change.yml)
- [Wiz Service Account Change](../rules/wiz_rules/wiz_service_account_change.yml)
- [Wiz Update IP Restrictions](../rules/wiz_rules/wiz_update_ip_restrictions.yml)
- [Wiz Update Login Settings](../rules/wiz_rules/wiz_update_login_settings.yml)
- [Wiz Update Scanner Settings](../rules/wiz_rules/wiz_update_scanner_settings.yml)
- [Wiz Update Support Contact List](../rules/wiz_rules/wiz_update_support_contact_list.yml)
- [Wiz User Created Or Deleted](../rules/wiz_rules/wiz_user_created_or_deleted.yml)
- [Wiz User Role Updated Or Deleted](../rules/wiz_rules/wiz_user_role_updated_or_deleted.yml)


# Z

- [Zeek](#zeek)
- [Zendesk](#zendesk)
- [Zoom](#zoom)
- [Zscaler](#zscaler)


## Zeek

- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)


## Zendesk

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
- [Enabled Zendesk Support to Assume Users](../rules/zendesk_rules/zendesk_user_assumption.yml)
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
- [Zendesk Account Owner Changed](../rules/zendesk_rules/zendesk_new_owner.yml)
- [Zendesk API Token Created](../rules/zendesk_rules/zendesk_new_api_token.yml)
- [Zendesk Credit Card Redaction Off](../rules/zendesk_rules/zendesk_sensitive_data_redaction.yml)
- [Zendesk Mobile App Access Modified](../rules/zendesk_rules/zendesk_mobile_app_access.yml)
- [Zendesk User Role Changed](../rules/zendesk_rules/zendesk_user_role.yml)
- [Zendesk User Suspension Status Changed](../rules/zendesk_rules/zendesk_user_suspension.yml)


## Zoom

- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
- [Zoom All Meetings Secured With One Option Disabled](../rules/zoom_operation_rules/zoom_all_meetings_secured_with_one_option_disabled.yml)
- [Zoom Automatic Sign Out Disabled](../rules/zoom_operation_rules/zoom_automatic_sign_out_disabled.yml)
- [Zoom Meeting Passcode Disabled](../rules/zoom_operation_rules/zoom_operation_passcode_disabled.yml)
- [Zoom New Meeting Passcode Required Disabled](../rules/zoom_operation_rules/zoom_new_meeting_passcode_required_disabled.yml)
- [Zoom Sign In Method Modified](../rules/zoom_operation_rules/zoom_sign_in_method_modified.yml)
- [Zoom Sign In Requirements Changed](../rules/zoom_operation_rules/zoom_sign_in_requirements_changed.yml)
- [Zoom Two Factor Authentication Disabled](../rules/zoom_operation_rules/zoom_two_factor_authentication_disabled.yml)
- [Zoom User Promoted to Privileged Role](../rules/zoom_operation_rules/zoom_user_promoted_to_privileged_role.yml)


## Zscaler

- [ZIA Account Access Removed](../rules/zscaler_rules/zia/zia_account_access_removal.yml)
- [ZIA Additional Cloud Roles](../rules/zscaler_rules/zia/zia_additional_cloud_roles.yml)
- [ZIA Backup Deleted](../rules/zscaler_rules/zia/zia_backup_deleted.yml)
- [ZIA Cloud Account Created](../rules/zscaler_rules/zia/zia_create_cloud_account.yml)
- [ZIA Golden Restore Point Dropped](../rules/zscaler_rules/zia/zia_golden_restore_point_dropped.yml)
- [ZIA Insecure Password Settings](../rules/zscaler_rules/zia/zia_insecure_password_settings.yml)
- [ZIA Log Streaming Disabled](../rules/zscaler_rules/zia/zia_log_streaming_disabled.yml)
- [ZIA Logs Downloaded](../rules/zscaler_rules/zia/zia_logs_downloaded.yml)
- [ZIA Password Expiration](../rules/zscaler_rules/zia/zia_password_expiration.yml)
- [ZIA Trust Modification](../rules/zscaler_rules/zia/zia_trust_modification.yml)


