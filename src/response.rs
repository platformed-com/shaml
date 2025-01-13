use libxml::{parser::Parser as XmlParser, xpath::Context};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use xmlsec::{XmlSecDocumentExt as _, XmlSecKey, XmlSecKeyFormat, XmlSecSignatureContext};

use crate::{
    utils::{decode_xml_base64, single_node},
    SamlError,
};

pub fn extract_response_issuer(input: &[u8]) -> Result<String, SamlError> {
    let parser = XmlParser::default();

    let document = parser.parse_string(input).map_err(SamlError::InvalidXml)?;

    let mut context = Context::new(&document).expect("Failed to create XPath context");
    context
        .register_namespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol")
        .expect("Failed to register namespace");
    context
        .register_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion")
        .expect("Failed to register namespace");
    context
        .findvalue("//saml2p:Response/saml2:Issuer/text()", None)
        .map_err(|_| SamlError::InvalidIssuer)
}

pub fn extract_response_subject(input: &[u8], name_format: &str) -> Result<String, SamlError> {
    let parser = XmlParser::default();

    let document = parser.parse_string(input).map_err(SamlError::InvalidXml)?;

    let mut context = Context::new(&document).expect("Failed to create XPath context");
    context
        .register_namespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol")
        .expect("Failed to register namespace");
    context
        .register_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion")
        .expect("Failed to register namespace");
    context
        .findvalue(
            &format!(
                "//saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID[@Format={:?}]/text()",
                name_format
            ),
            None,
        )
        .map_err(|_| SamlError::InvalidAssertion)
}

fn check_conditions(
    context: &mut Context,
    name_format: &str,
    now: OffsetDateTime,
    audience: &str,
) -> Result<(), SamlError> {
    let condition_node = single_node(&context
        .evaluate(&format!(
            "//saml2p:Response/saml2:Assertion[.//saml2:Subject/saml2:NameID[@Format={:?}]]/saml2:Conditions",
            name_format
        ))
        .map_err(|_| SamlError::InvalidAssertion)?)?;

    if let Ok(not_before) = context.findvalue("//@NotBefore", Some(&condition_node)) {
        let not_before = OffsetDateTime::parse(&not_before, &Iso8601::DEFAULT)
            .map_err(|_| SamlError::InvalidCondition)?;
        if now < not_before {
            return Err(SamlError::ConditionNotMet);
        }
    }

    if let Ok(not_on_or_after) = context.findvalue("//@NotOnOrAfter", Some(&condition_node)) {
        let not_on_or_after = OffsetDateTime::parse(&not_on_or_after, &Iso8601::DEFAULT)
            .map_err(|_| SamlError::InvalidCondition)?;
        if now >= not_on_or_after {
            return Err(SamlError::ConditionNotMet);
        }
    }

    if let Ok(audience_restriction) = context.findvalue(
        "//saml2:AudienceRestriction/saml2:Audience/text()",
        Some(&condition_node),
    ) {
        if audience != audience_restriction {
            return Err(SamlError::ConditionNotMet);
        }
    }

    Ok(())
}

pub fn decode_response(input: &str) -> Result<Vec<u8>, SamlError> {
    decode_xml_base64(input).map_err(|_| SamlError::InvalidResponse)
}

pub fn validate_response(
    input: &[u8],
    cert: &[u8],
    name_format: &str,
    now: OffsetDateTime,
    audience: &str,
) -> Result<String, SamlError> {
    let parser = XmlParser::default();

    let document = parser.parse_string(input).map_err(SamlError::InvalidXml)?;

    let key = XmlSecKey::from_memory(cert, XmlSecKeyFormat::CertDer, None)
        .expect("Failed to properly load cert");

    let mut sigctx = XmlSecSignatureContext::new();
    sigctx.insert_key(key);

    // optionaly specify the attribute ID names in the nodes you are verifying
    document
        .specify_idattr(
            "//saml2p:Response",
            "ID",
            Some(&[("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol")]),
        )
        .expect(
            "Could not specify ID attr name. This error specifies whether no nodes where found \
            or if there was an attr name collision.",
        );

    let valid = sigctx
        .verify_document(&document)
        .expect("Failed to verify document");

    if !valid {
        return Err(SamlError::InvalidSignature);
    }

    let mut context = Context::new(&document).expect("Failed to create XPath context");
    context
        .register_namespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol")
        .expect("Failed to register namespace");
    context
        .register_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion")
        .expect("Failed to register namespace");

    check_conditions(&mut context, name_format, now, audience)?;

    context
        .findvalue(
            &format!(
                "//saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID[@Format={:?}]/text()",
                name_format
            ),
            None,
        )
        .map_err(|_| SamlError::InvalidAssertion)
}

#[cfg(test)]
mod tests {
    use crate::{utils::decode_xml_base64, NAME_ID_FORMAT_EMAIL_ADDRESS};
    use time::{format_description::well_known::Iso8601, OffsetDateTime};

    const SAMPLE_RESPONSE: &[u8] = include_bytes!("../static/okta_response.xml");
    const SAMPLE_CERT_PEM: &str = include_str!("../static/okta.cert");

    use super::*;

    #[test]
    fn can_validate_response() {
        let cert = decode_xml_base64(
            SAMPLE_CERT_PEM
                .strip_prefix("-----BEGIN CERTIFICATE-----\n")
                .unwrap()
                .strip_suffix("-----END CERTIFICATE-----\n")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            extract_response_issuer(SAMPLE_RESPONSE).unwrap(),
            "http://www.okta.com/exkmfxqjjbEMEQMsR5d7"
        );

        validate_response(
            SAMPLE_RESPONSE,
            &cert,
            NAME_ID_FORMAT_EMAIL_ADDRESS,
            OffsetDateTime::parse("2025-01-08T16:31:18.814Z", &Iso8601::DEFAULT).unwrap(),
            "https://app.platformed.build:8080/saml/sp",
        )
        .unwrap();
    }
}
