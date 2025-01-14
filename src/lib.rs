use libxml::parser::XmlParseError;

mod authn_request;
mod idp_metadata;
mod response;
mod sp_metadata;
mod utils;

pub use authn_request::{AuthnRequestBuilder, ProtocolBinding};
pub use idp_metadata::parse_idp_metadata;
pub use response::{
    decode_response, extract_response_issuer, extract_response_subject, validate_response,
};
pub use sp_metadata::SpMetadataBuilder;

pub const NAME_ID_FORMAT_EMAIL_ADDRESS: &str =
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

#[derive(Debug)]
pub enum SamlError {
    InvalidResponse,
    InvalidXml(XmlParseError),
    InvalidSignature,
    InvalidAssertion,
    InvalidIssuer,
    InvalidMetadata,
    InvalidCondition,
    ConditionNotMet,
}
