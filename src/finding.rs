use aws_sdk_iam::{
    primitives::DateTime,
    types::{ServiceLastAccessed, TrackedActionLastAccessed},
};
use serde::Serialize;
use time::{Duration, OffsetDateTime};

#[derive(Serialize, Debug)]
pub struct Finding {
    pub resource: String,
    pub resource_type: ResourceType,
    pub resource_owner_account: String,
    pub id: String,
    pub finding_details: Vec<FindingDetails>,
    pub finding_type: FindingType,
}

#[derive(Serialize, Debug)]
pub enum ResourceType {
    AwsIamRole,
    AwsIamUser,
}

#[derive(Serialize, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum FindingType {
    UnusedIamRole,
    UnusedIamUserAccessKey,
    UnusedIamUserPassword,
    UnusedPermission,
}

#[derive(Serialize, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum FindingDetails {
    UnusedIamRoleDetails(UnusedIamRoleDetails),
    UnusedIamUserAccessKeyDetails(UnusedIamUserAccessKeyDetails),
    UnusedIamUserPasswordDetails(UnusedIamUserPasswordDetails),
    UnusedPermissionDetails(UnusedPermissionDetails),
}

#[derive(Serialize, Debug)]
pub struct UnusedIamRoleDetails {
    #[serde(with = "string")]
    pub last_accessed: Option<DateTime>,
}

#[derive(Serialize, Debug)]
pub struct UnusedIamUserAccessKeyDetails {
    #[serde(with = "string")]
    pub last_accessed: Option<DateTime>,
    pub access_key_id: String,
}

#[derive(Serialize, Debug)]
pub struct UnusedIamUserPasswordDetails {
    #[serde(with = "string")]
    pub last_accessed: Option<DateTime>,
}

#[derive(Serialize, Debug)]
pub struct UnusedPermissionDetails {
    pub actions: Option<Vec<UnusedAction>>,
    pub service_namespace: String,
    #[serde(with = "string")]
    pub last_accessed: Option<DateTime>,
}

#[derive(Serialize, Debug)]
pub struct UnusedAction {
    pub action: String,
    #[serde(with = "string")]
    pub last_accessed: Option<DateTime>,
}

impl From<TrackedActionLastAccessed> for UnusedAction {
    fn from(value: TrackedActionLastAccessed) -> Self {
        UnusedAction {
            action: value.action_name.unwrap_or_default(), // ? seems not possible to be None
            last_accessed: value.last_accessed_time,
        }
    }
}

impl From<ServiceLastAccessed> for UnusedPermissionDetails {
    fn from(value: ServiceLastAccessed) -> Self {
        UnusedPermissionDetails {
            actions: value
                .tracked_actions_last_accessed
                .map(|a| a.into_iter().map(Into::into).collect()),
            service_namespace: value.service_namespace,
            last_accessed: value.last_authenticated,
        }
    }
}

impl UnusedPermissionDetails {
    pub fn any_not_used(&self, analyzed_at: &OffsetDateTime, unused_access_age: i64) -> bool {
        duration_gt_age(self.last_accessed, analyzed_at, unused_access_age)
            || self.actions.as_ref().is_some_and(|actions| {
                actions
                    .iter()
                    .any(|action| duration_gt_age(action.last_accessed, analyzed_at, unused_access_age))
            })
    }
}

pub fn duration_gt_age(last_accessed: Option<DateTime>, analyzed_at: &OffsetDateTime, unused_access_age: i64) -> bool {
    match last_accessed {
        None => true,
        Some(last_accessed) => OffsetDateTime::from_unix_timestamp(last_accessed.secs())
            .is_ok_and(|last_accessed| *analyzed_at - last_accessed > Duration::days(unused_access_age)),
    }
}

mod string {
    use serde::Serializer;
    use std::fmt::Display;

    pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: Serializer,
    {
        if let Some(value) = value {
            serializer.collect_str(value)
        } else {
            serializer.serialize_none()
        }
    }
}
