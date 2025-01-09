use yaserde::YaSerialize;

#[derive(YaSerialize)]
#[yaserde(
  namespaces = {
    "md" = "urn:oasis:names:tc:SAML:2.0:metadata",
  },
  prefix = "md"
)]
struct EntityDescriptor {
    #[yaserde(attribute = true, rename = "entityID")]
    entity_id: String,
    #[yaserde(rename = "SPSSODescriptor", prefix = "md")]
    sp_sso_descriptor: SPSSODescriptor,
}

#[derive(YaSerialize)]
struct SPSSODescriptor {
    #[yaserde(attribute = true, rename = "AuthnRequestsSigned")]
    authn_requests_signed: bool,
    #[yaserde(attribute = true, rename = "WantAssertionsSigned")]
    want_assertions_signed: bool,
    #[yaserde(attribute = true, rename = "protocolSupportEnumeration")]
    protocol_support_enumeration: String,
    #[yaserde(rename = "NameIdFormat", prefix = "md")]
    name_id_format: NameIdFormat,
    #[yaserde(rename = "AssertionConsumerService", prefix = "md")]
    assertion_consumer_service: AssertionConsumerService,
}

#[derive(YaSerialize)]
struct NameIdFormat {
    #[yaserde(text = true)]
    content: String,
}

#[derive(YaSerialize)]
struct AssertionConsumerService {
    #[yaserde(attribute = true, rename = "Binding")]
    binding: String,
    #[yaserde(attribute = true, rename = "Location")]
    location: String,
    #[yaserde(attribute = true)]
    index: u32,
}

#[derive(Default)]
pub struct SpMetadataBuilder {
    entity_id: Option<String>,
    acs_url: Option<String>,
    name_id_format: Option<String>,
}

impl SpMetadataBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entity_id(self, entity_id: &str) -> Self {
        Self {
            entity_id: Some(entity_id.into()),
            ..self
        }
    }

    pub fn acs_url(self, acs_url: &str) -> Self {
        Self {
            acs_url: Some(acs_url.into()),
            ..self
        }
    }

    pub fn name_id_format(self, name_id_format: &str) -> Self {
        Self {
            name_id_format: Some(name_id_format.into()),
            ..self
        }
    }

    pub fn build(self) -> String {
        let metadata = EntityDescriptor {
            entity_id: self.entity_id.expect("entity_id is required"),
            sp_sso_descriptor: SPSSODescriptor {
                authn_requests_signed: false,
                want_assertions_signed: false,
                protocol_support_enumeration: "urn:oasis:names:tc:SAML:2.0:protocol".into(),
                name_id_format: NameIdFormat {
                    content: self.name_id_format.expect("name_id_format is required"),
                },
                assertion_consumer_service: AssertionConsumerService {
                    binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
                    location: self.acs_url.expect("acs_url is required"),
                    index: 0,
                },
            },
        };
        yaserde::ser::to_string(&metadata).expect("Infallible serialization")
    }
}

#[cfg(test)]
mod tests {
    use crate::NAME_ID_FORMAT_EMAIL_ADDRESS;

    use super::*;

    #[test]
    fn can_build_sp_metadata() {
        println!(
            "{}",
            SpMetadataBuilder::new()
                .entity_id("entity_id")
                .acs_url("https://foo.com/acs")
                .name_id_format(NAME_ID_FORMAT_EMAIL_ADDRESS)
                .build()
        );
    }
}
