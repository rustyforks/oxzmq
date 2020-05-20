//! This module defines convenience functions to help with parsing.

use std::convert::TryFrom;

/// Parse a single u8 from a slice.
///
/// ## Panics if:
/// - Provided slice length is not at least 1
pub(crate) fn parse_u8(i: &[u8]) -> (u8, &[u8]) {
    (
        u8::from_be_bytes(<[u8; 1]>::try_from(&i[0..1]).unwrap()),
        &i[1..],
    )
}
