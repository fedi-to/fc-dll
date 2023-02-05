// FC-DLL - An implementation of Fedi-To, for Windows 10 and later.
// Copyright (C) 2022-2023 Soni L.
// This software is made with love by a queer trans person.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_op_in_unsafe_fn)]

use ltptr::ConstLtPtr;
use ltptr::FromLtPtr as _;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use windows::Foundation::Uri;
use windows::System::{Launcher, LauncherOptions};

use std::ffi::CStr;

/// Opens the given C string-encoded URI, which must use a `web+*` scheme.
///
/// The C string must be UTF-8, and must not be a null pointer.
///
/// Returns 0 on failure, 1 on success.
#[no_mangle]
pub unsafe extern "C" fn fc_open_uri(uri: ConstLtPtr<'_, std::ffi::c_char>) -> i32 {
    // SAFETY: guaranteed by API contract.
    let Ok(uri) = unsafe { CStr::from_lt_ptr(uri) }.to_str() else {
        return 0
    };

    match fc_open_uri_inner(uri) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn fc_open_uri_inner(uri: &str) -> Result<(), Box<dyn std::error::Error>> {
    let fallback = get_fallback(uri)?;
    let uri = From::from(uri);
    let uri = Uri::CreateUri(&uri)?;
    let fallback = From::from(fallback);
    let fallback = Uri::CreateUri(&fallback)?;
    let options = LauncherOptions::new()?;
    options.SetFallbackUri(&fallback)?;
    // we do not care about the result of the `IAsyncOperation<bool>`, since we
    // are providing a fallback. we do propagate the `Result` tho.
    let _ = Launcher::LaunchUriWithOptionsAsync(&uri, &options)?;
    Ok(())
}

// Fedi-To get_fallback implementation

const COMPONENT: &'static AsciiSet = &{
    // start with CONTROLS
    CONTROLS
    // add query
    .add(b' ').add(b'"').add(b'#').add(b'<').add(b'>')
    // add path
    .add(b'?').add(b'`').add(b'{').add(b'}')
    // add userinfo
    .add(b'/').add(b':').add(b';').add(b'=').add(b'@').add(b'[').add(b'\\')
    .add(b']').add(b'^').add(b'|')
    // finish off with component
    .add(b'$').add(b'%').add(b'&').add(b'+').add(b',')
};


/// Error kind returned when trying to find the fallback protocol handler.
#[derive(Copy, Clone, Debug)]
enum FallbackError {
    /// Returned when the given URL, while valid, does not provide a fallback
    /// handler.
    NoHandler,
    /// Returned when the given target is not an URL.
    NotAnUrl,
}

impl std::error::Error for FallbackError {
}

impl std::fmt::Display for FallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoHandler => {
                write!(f, "url does not contain a fallback handler")
            },
            Self::NotAnUrl => {
                write!(f, "url is not an appropriate web+ url")
            },
        }
    }
}

/// Checks whether the `scheme` part of `web+scheme` satisfies the desired
/// constraints.
fn is_scheme_invalid(scheme: &str) -> bool {
    // valid schemes are non-empty and are entirely ascii lowercase
    // so invalid schemes are empty or contain non-ascii-lowercase.
    scheme.is_empty() || !scheme.trim_start_matches(|c: char| -> bool {
        c.is_ascii_lowercase()
    }).is_empty()
}

/// Attempts to find a fallback protocol handler for the given target URL.
///
/// The target is assumed to be normalized, as per the WHATWG URL spec. (Note
/// that Fedi-To doesn't actually check that it is, but that's a Fedi-To
/// issue.)
fn get_fallback(target: &str) -> Result<String, FallbackError> {
    use FallbackError::*;
    // find the scheme
    let scheme = {
        let colon = target.find(':').ok_or(NotAnUrl)?;
        let scheme = &target[..colon];
        if !scheme.starts_with("web+") {
            return Err(NotAnUrl);
        }
        let scheme = &scheme[4..];
        if is_scheme_invalid(scheme) {
            return Err(NotAnUrl);
        }
        scheme
    };
    // replace web+scheme with https
    // this allows us to handle web+ URLs with the semantics we actually
    // want, which is roughly the same as https, with a few differences
    let mut as_if_https = target.to_string();
    as_if_https.replace_range(0..4+scheme.len(), "https");
    // the main difference is that unlike https, authority is optional.
    // so, first check that there should be an authority.
    if !as_if_https.starts_with("https://") {
        return Err(NoHandler);
    }
    // then also check that the authority actually exists.
    // this is necessary so we don't end up parsing web+example:///bar as
    // web+example://bar/ (which would be wrong).
    // note that we do parse web+example://bar\ as an authority! (but
    // everything else - like the path - we treat as opaque to us)
    if as_if_https.starts_with("https:///")
    || as_if_https.starts_with("https://\\") {
        return Err(NoHandler);
    }
    // NOTE: we only do this parse to extract the domain/port, it is up to
    // the protocol-handler to deal with malformed or malicious input.
    // NOTE: this is the same URL parser as used by browsers when handling
    // `href` so this is correct.
    let mut url = url::Url::parse(&*as_if_https).map_err(|_| NoHandler)?;
    url.set_path("/.well-known/protocol-handler");
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let mut params = "target=".to_owned();
    params.extend(utf8_percent_encode(&*target, COMPONENT));
    url.set_query(Some(&*params));
    url.set_fragment(None);
    Ok(url.into())
}
