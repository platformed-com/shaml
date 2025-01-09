use libxml::parser::XmlParseError;

mod authn_request;
mod idp_metadata;
mod response;
mod sp_metadata;
mod utils;

pub use authn_request::AuthnRequestBuilder;
pub use idp_metadata::parse_idp_metadata;
pub use response::{extract_response_issuer, validate_response};
pub use sp_metadata::SpMetadataBuilder;

pub const NAME_ID_FORMAT_EMAIL_ADDRESS: &str =
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

#[derive(Debug)]
pub enum SamlError {
    InvalidXml(XmlParseError),
    InvalidSignature,
    InvalidAssertion,
    InvalidIssuer,
    InvalidMetadata,
    InvalidCondition,
    ConditionNotMet,
}
