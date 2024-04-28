#![allow(unused)]
#![allow(unused_variables)]

use std::alloc::System;
use time::{Duration, OffsetDateTime};

use aws_sdk_iam::{
    primitives::DateTime,
    types::{Role, ServiceLastAccessed, User},
    Client,
};

use crate::finding::{
    Finding, FindingDetails, FindingType, ResourceType, UnusedIamRoleDetails, UnusedIamUserAccessKeyDetails,
    UnusedIamUserPasswordDetails, UnusedPermissionDetails,
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
            if OffsetDateTime::from_unix_timestamp(user.create_date.secs())
                .is_ok_and(|created| now - created < Duration::days(self.unused_access_age))
            {
                continue;
            }
            result.append(&mut self.analyze_user(iam_client, user).await?);
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
            if OffsetDateTime::from_unix_timestamp(role.create_date.secs())
                .is_ok_and(|created| now - created < Duration::days(self.unused_access_age))
            {
                continue;
            }
            result.append(&mut self.analyze_role(iam_client, role).await?);
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
        if login_profile.is_some_and(|login_profile| {
            OffsetDateTime::from_unix_timestamp(login_profile.create_date.secs())
                .is_ok_and(|created| now - created > Duration::days(self.unused_access_age))
        }) {
            if let Some(detail) = check_last_accessed_detail(&now, self.unused_access_age, user.password_last_used) {
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
            { iam_client.list_access_keys().user_name(&user.user_name).send().await? }.access_key_metadata;
        for access_key in access_keys {
            if access_key.create_date.is_some_and(|created| {
                OffsetDateTime::from_unix_timestamp(created.secs())
                    .is_ok_and(|created| now - created > Duration::days(self.unused_access_age))
            }) {
                if let Some(access_key_id) = access_key.access_key_id {
                    let last_access = iam_client
                        .get_access_key_last_used()
                        .access_key_id(&access_key_id)
                        .send()
                        .await?;
                    if let Some(detail) = check_last_accessed_detail(
                        &now,
                        self.unused_access_age,
                        last_access
                            .access_key_last_used
                            .map(|last_access| last_access.last_used_date),
                    ) {
                        result.push(Finding {
                            resource: user.arn.clone(),
                            resource_type: ResourceType::AwsIamUser,
                            resource_owner_account: self.owner_account.clone(),
                            id: uuid::Uuid::new_v4().to_string(),
                            finding_details: vec![FindingDetails::UnusedIamUserAccessKeyDetails(
                                UnusedIamUserAccessKeyDetails {
                                    last_accessed: detail,
                                    access_key_id,
                                },
                            )],
                            finding_type: FindingType::UnusedIamUserAccessKey,
                        })
                    }
                }
            }
        }

        let unused_permission_details: Vec<_> = self
            .get_last_accessed(iam_client, &user.arn)
            .await?
            .into_iter()
            .filter_map(|last_accessed| {
                let details = Into::<UnusedPermissionDetails>::into(last_accessed);
                if details.all_used(&now, self.unused_access_age) {
                    None
                } else {
                    Some(FindingDetails::UnusedPermissionDetails(details))
                }
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

    async fn analyze_role(&self, iam_client: &Client, role: Role) -> anyhow::Result<Vec<Finding>> {
        let now = OffsetDateTime::now_utc();
        let mut result = vec![];

        if let Some(detail) = check_last_accessed_detail(
            &now,
            self.unused_access_age,
            role.role_last_used.and_then(|last_used| last_used.last_used_date),
        ) {
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
                if details.all_used(&now, self.unused_access_age) {
                    None
                } else {
                    Some(FindingDetails::UnusedPermissionDetails(details))
                }
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
        let now = OffsetDateTime::now_utc();
        let job_id = iam_client
            .generate_service_last_accessed_details()
            .arn(arn)
            .send()
            .await?
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
                    anyhow::anyhow!("job status invalid?");
                }
            }
        }
        Err(anyhow::anyhow!("timeout"))?
    }
}

type LastAccessedDetail = Option<DateTime>;
fn check_last_accessed_detail(
    analyzed_at: &OffsetDateTime,
    unused_access_age: i64,
    last_used_at: Option<DateTime>,
) -> Option<LastAccessedDetail> {
    if last_used_at.is_some_and(|last_used_at| {
        OffsetDateTime::from_unix_timestamp(last_used_at.secs())
            .is_ok_and(|last_used_at| *analyzed_at - last_used_at < Duration::days(unused_access_age))
    }) {
        None
    } else {
        Some(last_used_at.map(Into::into))
    }
}
