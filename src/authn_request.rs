use std::{fmt::Display, str::FromStr};

use base64::{prelude::BASE64_STANDARD, Engine};
use deflate::deflate_bytes;
use time::OffsetDateTime;
use yaserde::YaSerialize;

use crate::{utils::random_string, DATE_TIME_FORMAT};

#[derive(YaSerialize)]
#[yaserde(
  namespaces = {
    "samlp" = "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml" = "urn:oasis:names:tc:SAML:2.0:assertion",
  },
  prefix = "samlp"
)]
struct AuthnRequest {
    #[yaserde(attribute = true, rename = "ID")]
    id: String,
    #[yaserde(attribute = true, rename = "Version")]
    version: String,
    #[yaserde(attribute = true, rename = "IssueInstant")]
    issue_instant: String,
    #[yaserde(attribute = true, rename = "Destination")]
    destination: String,
    #[yaserde(attribute = true, rename = "ProtocolBinding")]
    protocol_binding: String,
    #[yaserde(attribute = true, rename = "AssertionConsumerServiceURL")]
    assertion_consumer_service_url: String,
    #[yaserde(rename = "Issuer", prefix = "saml")]
    issuer: Issuer,
    #[yaserde(rename = "NameIdPolicy", prefix = "samlp")]
    name_id_policy: NameIdPolicy,
    #[yaserde(rename = "Subject", prefix = "saml")]
    subject: Option<Subject>,
}

#[derive(YaSerialize)]
struct Issuer {
    #[yaserde(attribute = true, rename = "Format")]
    format: String,
    #[yaserde(text = true)]
    content: String,
}

#[derive(YaSerialize)]
struct NameIdPolicy {
    #[yaserde(attribute = true, rename = "Format")]
    format: String,
    #[yaserde(attribute = true, rename = "AllowCreate")]
    allow_create: bool,
}

#[derive(YaSerialize)]
struct Subject {
    #[yaserde(rename = "NameId", prefix = "saml")]
    name_id: NameId,
}

#[derive(YaSerialize)]
struct NameId {
    #[yaserde(attribute = true, rename = "Format")]
    format: String,
    #[yaserde(text = true)]
    content: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolBinding {
    Post,
    #[default]
    Redirect,
}

impl Display for ProtocolBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProtocolBinding::Post => write!(f, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
            ProtocolBinding::Redirect => {
                write!(f, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
            }
        }
    }
}

impl FromStr for ProtocolBinding {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Ok(ProtocolBinding::Post),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" => Ok(ProtocolBinding::Redirect),
            _ => Err(()),
        }
    }
}

#[derive(Default)]
pub struct AuthnRequestBuilder {
    id: Option<String>,
    issue_instant: Option<OffsetDateTime>,
    issuer: Option<String>,
    destination: Option<String>,
    protocol_binding: ProtocolBinding,
    consumer_url: Option<String>,
    name_format: Option<String>,
    deny_create: bool,
    subject: Option<String>,
}

impl AuthnRequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn id(self, id: &str) -> Self {
        AuthnRequestBuilder {
            id: Some(id.into()),
            ..self
        }
    }

    pub fn auto_id(self) -> Self {
        AuthnRequestBuilder {
            id: Some(format!("_id{}", random_string(32))),
            ..self
        }
    }

    pub fn issue_instant(self, instant: OffsetDateTime) -> Self {
        AuthnRequestBuilder {
            issue_instant: Some(instant),
            ..self
        }
    }

    pub fn issued_now(self) -> Self {
        AuthnRequestBuilder {
            issue_instant: Some(OffsetDateTime::now_utc()),
            ..self
        }
    }

    pub fn issuer(self, issuer: &str) -> Self {
        AuthnRequestBuilder {
            issuer: Some(issuer.into()),
            ..self
        }
    }

    pub fn destination(self, destination: &str) -> Self {
        AuthnRequestBuilder {
            destination: Some(destination.into()),
            ..self
        }
    }

    pub fn protocol_binding(self, binding: ProtocolBinding) -> Self {
        AuthnRequestBuilder {
            protocol_binding: binding,
            ..self
        }
    }

    pub fn consumer_url(self, url: &str) -> Self {
        AuthnRequestBuilder {
            consumer_url: Some(url.into()),
            ..self
        }
    }

    pub fn name_format(self, format: &str) -> Self {
        AuthnRequestBuilder {
            name_format: Some(format.into()),
            ..self
        }
    }

    pub fn allow_create(self, allow: bool) -> Self {
        AuthnRequestBuilder {
            deny_create: !allow,
            ..self
        }
    }

    pub fn subject(self, subject: &str) -> Self {
        AuthnRequestBuilder {
            subject: Some(subject.into()),
            ..self
        }
    }

    pub fn build(self) -> String {
        let req = AuthnRequest {
            id: self.id.expect("ID is required"),
            version: "2.0".to_string(),
            issue_instant: self
                .issue_instant
                .expect("IssueInstant is required")
                .format(&DATE_TIME_FORMAT)
                .expect("Infallible formatting"),
            destination: self.destination.expect("Destination is required"),
            protocol_binding: self.protocol_binding.to_string(),
            assertion_consumer_service_url: self.consumer_url.expect("Consumer URL is required"),
            issuer: Issuer {
                format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity".to_string(),
                content: self.issuer.expect("Issuer is required"),
            },
            name_id_policy: NameIdPolicy {
                format: self.name_format.clone().expect("Name format is required"),
                allow_create: !self.deny_create,
            },
            subject: self.subject.map(|subject| Subject {
                name_id: NameId {
                    format: self.name_format.clone().expect("Name format is required"),
                    content: subject,
                },
            }),
        };
        yaserde::ser::to_string(&req).expect("Infallible serialization")
    }

    pub fn build_and_encode(self) -> String {
        let xml = self.build();
        let compressed = deflate_bytes(xml.as_bytes());
        BASE64_STANDARD.encode(compressed)
    }
}

#[cfg(test)]
mod tests {
    use crate::NAME_ID_FORMAT_EMAIL_ADDRESS;

    use super::*;

    #[test]
    fn can_build_authn_request() {
        println!(
            "{}",
            AuthnRequestBuilder::new()
                .auto_id()
                .issued_now()
                .issuer("issuer")
                .destination("destination")
                .consumer_url("consumer_url")
                .name_format(NAME_ID_FORMAT_EMAIL_ADDRESS)
                .subject("subject")
                .build()
        );
    }
}
