use base64::{prelude::BASE64_STANDARD, Engine};
use libxml::{tree::Node, xpath::Object};
use rand::distributions::{Alphanumeric, DistString};

use crate::SamlError;

pub fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}

pub fn single_node(object: &Object) -> Result<Node, SamlError> {
    let mut nodes = object.get_nodes_as_vec();
    if nodes.len() != 1 {
        return Err(SamlError::InvalidAssertion);
    }
    Ok(nodes.remove(0))
}

pub fn decode_xml_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let stripped = input.replace([' ', '\n', '\r', '\t'], "");
    BASE64_STANDARD.decode(stripped)
}
