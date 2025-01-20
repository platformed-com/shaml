use libxml::parser::XmlParseError;

mod authn_request;
mod idp_metadata;
mod response;
mod sp_metadata;
mod utils;

pub use authn_request::{AuthnRequestBuilder, ProtocolBinding};
pub use idp_metadata::{parse_idp_metadata, IdpMetadata};
pub use response::{
    decode_response, extract_response_issuer, extract_response_subject, validate_response,
};
pub use sp_metadata::SpMetadataBuilder;
use time::format_description::well_known::iso8601::{self, TimePrecision};

pub const NAME_ID_FORMAT_EMAIL_ADDRESS: &str =
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

// xs:dateTime isn't actually ISO8601, because implementors often don't support higher precisions.
pub const DATE_TIME_FORMAT: iso8601::Iso8601<
    {
        iso8601::Config::DEFAULT
            .set_time_precision(TimePrecision::Second {
                decimal_digits: None,
            })
            .encode()
    },
> = iso8601::Iso8601;

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
