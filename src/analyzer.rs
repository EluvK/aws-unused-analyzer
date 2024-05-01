use time::OffsetDateTime;

use aws_sdk_iam::{
    types::{AccessAdvisorUsageGranularityType, ServiceLastAccessed, User},
    Client,
};

use crate::finding::{
    duration_gt_age, Finding, FindingDetails, FindingType, ResourceType, UnusedIamRoleDetails,
    UnusedIamUserAccessKeyDetails, UnusedIamUserPasswordDetails, UnusedPermissionDetails,
};

pub struct MetaData {
    pub unused_access_age: i64,
    pub owner_account: String,
}

impl MetaData {
    pub async fn analyze(&self, iam_client: &Client) -> anyhow::Result<Vec<Finding>> {
        self.analyze_account(iam_client).await
    }

    async fn analyze_account(&self, iam_client: &Client) -> anyhow::Result<Vec<Finding>> {
        let now = OffsetDateTime::now_utc();
        let mut result = vec![];

        let users = {
            let mut users = vec![];
            let mut next_marker = None;
            loop {
                let mut list_users_output = iam_client.list_users().set_marker(next_marker).send().await?;
                users.append(&mut list_users_output.users);
                if list_users_output.is_truncated {
                    next_marker = list_users_output.marker;
                } else {
                    break;
                }
            }
            users
        };

        for user in users {
            if duration_gt_age(Some(user.create_date), &now, self.unused_access_age) {
                result.append(&mut self.analyze_user(iam_client, user).await?);
            }
        }

        let roles = {
            let mut roles = vec![];
            let mut next_marker = None;
            loop {
                let mut list_roles_output = iam_client.list_roles().set_marker(next_marker).send().await?;
                roles.append(&mut list_roles_output.roles);
                if list_roles_output.is_truncated {
                    next_marker = list_roles_output.marker;
                } else {
                    break;
                }
            }
            roles
        };
        for role in roles {
            if role.path().starts_with("/aws-service-role/") {
                continue; // ignore service role
            }
            if duration_gt_age(Some(role.create_date), &now, self.unused_access_age) {
                result.append(&mut self.analyze_role(iam_client, role.role_name()).await?);
            }
        }

        Ok(result)
    }

    async fn analyze_user(&self, iam_client: &Client, user: User) -> anyhow::Result<Vec<Finding>> {
        let now = OffsetDateTime::now_utc();
        let mut result = vec![];
        let login_profile = {
            match iam_client.get_login_profile().user_name(&user.user_name).send().await {
                Ok(resp) => resp.login_profile,
                Err(e) if e.as_service_error().map(|e| e.is_no_such_entity_exception()) == Some(true) => None,
                Err(e) => return Err(e)?,
            }
        };
        if login_profile
            .is_some_and(|login_profile| duration_gt_age(Some(login_profile.create_date), &now, self.unused_access_age))
        {
            let last_access = user.password_last_used;
            if let Some(detail) = duration_gt_age(last_access, &now, self.unused_access_age).then_some(last_access) {
                result.push(Finding {
                    resource: user.arn.clone(),
                    resource_type: ResourceType::AwsIamUser,
                    resource_owner_account: self.owner_account.clone(),
                    id: uuid::Uuid::new_v4().to_string(),
                    finding_details: vec![FindingDetails::UnusedIamUserPasswordDetails(
                        UnusedIamUserPasswordDetails { last_accessed: detail },
                    )],
                    finding_type: FindingType::UnusedIamUserPassword,
                })
            }
        }

        let access_keys =
            { iam_client.list_access_keys().user_name(&user.user_name).send().await }?.access_key_metadata;

        let mut unused_access_key_details = vec![];
        for access_key in access_keys {
            if duration_gt_age(access_key.create_date, &now, self.unused_access_age) {
                if let Some(access_key_id) = access_key.access_key_id {
                    let last_access = iam_client
                        .get_access_key_last_used()
                        .access_key_id(&access_key_id)
                        .send()
                        .await?;
                    // aws last_access use Some(UNIX_EPOCH) as None..., map it back
                    let last_access = last_access.access_key_last_used.and_then(|last_access| {
                        (last_access.last_used_date.secs() != 0).then_some(last_access.last_used_date)
                    });
                    if let Some(detail) =
                        duration_gt_age(last_access, &now, self.unused_access_age).then_some(last_access)
                    {
                        unused_access_key_details.push(FindingDetails::UnusedIamUserAccessKeyDetails(
                            UnusedIamUserAccessKeyDetails {
                                last_accessed: detail,
                                access_key_id,
                            },
                        ));
                    }
                }
            }
        }
        if !unused_access_key_details.is_empty() {
            result.push(Finding {
                resource: user.arn.clone(),
                resource_type: ResourceType::AwsIamUser,
                resource_owner_account: self.owner_account.clone(),
                id: uuid::Uuid::new_v4().to_string(),
                finding_details: unused_access_key_details,
                finding_type: FindingType::UnusedIamUserAccessKey,
            })
        }

        let unused_permission_details: Vec<_> = self
            .get_last_accessed(iam_client, &user.arn)
            .await?
            .into_iter()
            .filter_map(|last_accessed| {
                let details = Into::<UnusedPermissionDetails>::into(last_accessed);
                details
                    .any_not_used(&now, self.unused_access_age)
                    .then_some(FindingDetails::UnusedPermissionDetails(details))
            })
            .collect();
        if !unused_permission_details.is_empty() {
            result.push(Finding {
                resource: user.arn.clone(),
                resource_type: ResourceType::AwsIamUser,
                resource_owner_account: self.owner_account.clone(),
                id: uuid::Uuid::new_v4().to_string(),
                finding_details: unused_permission_details,
                finding_type: FindingType::UnusedPermission,
            })
        }

        Ok(result)
    }

    async fn analyze_role(&self, iam_client: &Client, role_name: &str) -> anyhow::Result<Vec<Finding>> {
        let now = OffsetDateTime::now_utc();
        let mut result = vec![];

        let role = { iam_client.get_role().role_name(role_name).send().await }?
            .role
            .ok_or(anyhow::anyhow!("role not found"))?;

        let last_access = role.role_last_used.and_then(|last_used| last_used.last_used_date);
        if let Some(detail) = duration_gt_age(last_access, &now, self.unused_access_age).then_some(last_access) {
            result.push(Finding {
                resource: role.arn.clone(),
                resource_type: ResourceType::AwsIamRole,
                resource_owner_account: self.owner_account.clone(),
                id: uuid::Uuid::new_v4().to_string(),
                finding_details: vec![FindingDetails::UnusedIamRoleDetails(UnusedIamRoleDetails {
                    last_accessed: detail,
                })],
                finding_type: FindingType::UnusedIamRole,
            })
        }

        let unused_permission_details: Vec<_> = self
            .get_last_accessed(iam_client, &role.arn)
            .await?
            .into_iter()
            .filter_map(|last_accessed| {
                let details = Into::<UnusedPermissionDetails>::into(last_accessed);
                details
                    .any_not_used(&now, self.unused_access_age)
                    .then_some(FindingDetails::UnusedPermissionDetails(details))
            })
            .collect();
        if !unused_permission_details.is_empty() {
            result.push(Finding {
                resource: role.arn.clone(),
                resource_type: ResourceType::AwsIamRole,
                resource_owner_account: self.owner_account.clone(),
                id: uuid::Uuid::new_v4().to_string(),
                finding_details: unused_permission_details,
                finding_type: FindingType::UnusedPermission,
            })
        }

        Ok(result)
    }

    async fn get_last_accessed(&self, iam_client: &Client, arn: &str) -> anyhow::Result<Vec<ServiceLastAccessed>> {
        let job_id = {
            iam_client
                .generate_service_last_accessed_details()
                .arn(arn)
                .granularity(AccessAdvisorUsageGranularityType::ActionLevel)
                .send()
                .await
        }?
        .job_id
        .ok_or(anyhow::anyhow!("without job id while get last accessed details"))?;
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let report = iam_client
                .get_service_last_accessed_details()
                .job_id(&job_id)
                .send()
                .await?;
            match report.job_status {
                aws_sdk_iam::types::JobStatusType::Completed => {
                    return Ok(report.services_last_accessed);
                }
                aws_sdk_iam::types::JobStatusType::InProgress => {}
                status => {
                    anyhow::bail!("job status invalid: status:{status}");
                }
            }
        }
        anyhow::bail!("timeout");
    }
}
