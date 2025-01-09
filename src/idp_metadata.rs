use std::collections::HashMap;

use libxml::{parser::Parser as XmlParser, xpath::Context};

use crate::{authn_request::ProtocolBinding, utils::decode_xml_base64, SamlError};

#[derive(Debug)]
#[non_exhaustive]
pub struct IdpMetadata {
    pub entity_id: String,
    pub signing_certificate: Vec<u8>,
    pub sso_bindings: HashMap<ProtocolBinding, String>,
}

pub fn parse_idp_metadata(input: &[u8]) -> Result<IdpMetadata, SamlError> {
    let parser = XmlParser::default();

    let document = parser.parse_string(input).map_err(SamlError::InvalidXml)?;

    let mut context = Context::new(&document).expect("Failed to create XPath context");
    context
        .register_namespace("md", "urn:oasis:names:tc:SAML:2.0:metadata")
        .expect("Failed to register namespace");
    context
        .register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        .expect("Failed to register namespace");

    let entity_id = context
        .findvalue("//md:EntityDescriptor/@entityID", None)
        .map_err(|_| SamlError::InvalidMetadata)?;

    let encoded_certificate = context
    .findvalue("//md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use=\"signing\"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()", None)
    .map_err(|_| SamlError::InvalidMetadata)?;
    let signing_certificate = decode_xml_base64(&encoded_certificate).map_err(|e| {
        dbg!(e);
        SamlError::InvalidMetadata
    })?;

    let sso_nodes = context
        .evaluate("//md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService")
        .map_err(|_| SamlError::InvalidMetadata)?
        .get_nodes_as_vec();

    let mut sso_bindings = HashMap::new();
    for sso_node in sso_nodes {
        if let Ok(binding) = sso_node
            .get_attribute("Binding")
            .ok_or(SamlError::InvalidMetadata)?
            .parse()
        {
            let location = sso_node
                .get_attribute("Location")
                .ok_or(SamlError::InvalidMetadata)?;
            sso_bindings.insert(binding, location);
        }
    }

    Ok(IdpMetadata {
        entity_id,
        signing_certificate,
        sso_bindings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_METADATA: &[u8] = include_bytes!("../static/okta_metadata.xml");

    #[test]
    fn can_parse_idp_metadata() {
        let metadata = parse_idp_metadata(SAMPLE_METADATA).unwrap();
        dbg!(metadata);
    }
}
