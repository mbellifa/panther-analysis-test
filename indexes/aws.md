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
- [AWS Potentially Stolen Service Role](../queries/aws_queries/aws_potentially_compromised_service_role.yml)
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
- [Kubernetes Cron Job Created or Modified](../queries/kubernetes_queries/kubernetes_cron_job_created_or_modified_query.yml)
- [Kubernetes Pod Created in Pre-Configured or Default Name Spaces](../queries/kubernetes_queries/kubernetes_pod_in_default_name_space_query.yml)
- [New Admission Controller Created](../queries/kubernetes_queries/kubernetes_admission_controller_created.yml)
- [New DaemonSet Deployed to Kubernetes](../queries/kubernetes_queries/kubernetes_new_daemonset_deployed.yml)
- [Pod attached to the Node Host Network](../queries/kubernetes_queries/kubernetes_pod_attached_to_node_host_network.yml)
- [Pod Created or Modified Using the Host IPC Namespace](../queries/kubernetes_queries/kubernetes_pod_using_host_ipc_namespace_query.yml)
- [Pod Created or Modified Using the Host PID Namespace](../queries/kubernetes_queries/kubernetes_pod_using_host_pid_namespace.yml)
- [Pod Created with Overly Permissive Linux Capabilities](../queries/kubernetes_queries/kubernetes_overly_permissive_linux_capabilities.yml)
- [Pod creation or modification to a Host Path Volume Mount](../queries/kubernetes_queries/kubernetes_pod_create_or_modify_host_path_vol_mount_query.yml)
- [Privileged Pod Created](../queries/kubernetes_queries/kubernetes_privileged_pod_created_query.yml)
- [Secret Enumeration by a User](../queries/kubernetes_queries/kubernetes_secret_enumeration_query.yml)
- [Unauthenticated Kubernetes API Request](../queries/kubernetes_queries/kubernetes_unauthenticated_api_request.yml)
- [Unauthorized Kubernetes Pod Execution](../queries/kubernetes_queries/kubernetes_unauthorized_pod_execution.yml)


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
- [VPC Flow Port Scanning](../queries/aws_queries/anomalous_vpc_port_activity_query.yml)


## AWS WAF

- [AWS WAF Has XSS Predicate](../policies/aws_waf_policies/aws_waf_has_xss_predicate.yml)
- [AWS WAF Logging Configured](../policies/aws_waf_policies/aws_waf_logging_configured.yml)
- [AWS WAF Rule Ordering](../policies/aws_waf_policies/aws_waf_rule_ordering.yml)
- [AWS WAF WebACL Has Associated Resources](../policies/aws_waf_policies/aws_waf_webacl_has_associated_resources.yml)


