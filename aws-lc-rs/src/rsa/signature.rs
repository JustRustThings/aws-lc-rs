// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::ffi::c_int;
use std::fmt::{self, Debug, Formatter};
use std::ops::RangeInclusive;

use crate::aws_lc::{
    EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_CTX_set_signature_md,
    EVP_PKEY_bits, RSA_bits, EVP_PKEY, EVP_PKEY_CTX, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST,
};

use crate::digest::{self, match_digest_type, Digest};
use crate::error::Unspecified;
use crate::ptr::LcPtr;
use crate::rsa::key::parse_rsa_public_key;
use crate::sealed::Sealed;
use crate::signature::{ParsedPublicKey, ParsedVerificationAlgorithm, VerificationAlgorithm};

use super::encoding;
#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

#[allow(non_camel_case_types)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Eq, PartialEq)]
pub enum RsaPadding {
    RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING,
}

/// An RSA-PSS padding salt length.
#[expect(clippy::module_name_repetitions)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RsaPssSaltLength {
    /// The salt length is set to the length of the used digest algorithm.
    ///
    /// Corresponds to [`RSA_PSS_SALTLEN_DIGEST`]. This is the default.
    #[default]
    Digest,
    /// The salt length is set to the maximum possible length with respect to
    /// the used digest algorithm.
    Max,
    /// The salt length is set to the given custom value.
    ///
    /// The passed value is not particularly checked, so may result in failures.
    Custom(u16),
}

impl RsaPssSaltLength {
    pub(crate) fn into_value(
        self,
        algorithm: &'static digest::Algorithm,
        public_key: &LcPtr<EVP_PKEY>,
    ) -> c_int {
        match self {
            RsaPssSaltLength::Digest => RSA_PSS_SALTLEN_DIGEST,
            RsaPssSaltLength::Max => {
                let digest_len: u16 = algorithm.output_len().try_into().unwrap_or_default();
                let digest_len: c_int = digest_len.cast_signed().into();
                let key_size = unsafe { EVP_PKEY_bits(public_key.as_const_ptr()) };
                let em_len = (key_size + 6) / 8;
                em_len - digest_len - 2
            }
            RsaPssSaltLength::Custom(val) => val.cast_signed().into(),
        }
    }
}

/// Parameters for RSA verification.
///
/// Two values are equal when they denote the same verification algorithm, e.g.
/// `RSA_PKCS1_2048_8192_SHA256`. Algorithms differing in digest algorithm,
/// padding scheme or modulus size range compare unequal.
#[derive(Eq, PartialEq)]
pub struct RsaParameters {
    digest_alg: &'static digest::Algorithm,
    padding: &'static RsaPadding,
    pss_saltlen: Option<RsaPssSaltLength>,
    range: RangeInclusive<u32>,
    verification_alg: &'static RsaVerificationAlgorithmId,
}

impl RsaParameters {
    #[inline]
    pub(crate) fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest_alg
    }

    #[inline]
    pub(crate) fn padding(&self) -> &'static RsaPadding {
        self.padding
    }

    #[inline]
    pub(crate) fn pss_saltlen(&self) -> Option<RsaPssSaltLength> {
        self.pss_saltlen
    }

    #[inline]
    pub(crate) fn bit_size_range(&self) -> &RangeInclusive<u32> {
        &self.range
    }
}

impl ParsedVerificationAlgorithm for RsaParameters {
    fn parsed_verify_sig(
        &self,
        public_key: &ParsedPublicKey,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = public_key.key();
        verify_rsa_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_saltlen,
            evp_pkey,
            msg,
            signature,
            self.bit_size_range(),
        )
    }

    fn parsed_verify_digest_sig(
        &self,
        public_key: &ParsedPublicKey,
        digest: &Digest,
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = public_key.key();
        verify_rsa_digest_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_saltlen,
            evp_pkey,
            digest,
            signature,
            self.bit_size_range(),
        )
    }
}

impl VerificationAlgorithm for RsaParameters {
    #[cfg(feature = "ring-sig-verify")]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        self.verify_sig(
            public_key.as_slice_less_safe(),
            msg.as_slice_less_safe(),
            signature.as_slice_less_safe(),
        )
    }

    fn verify_sig(
        &self,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = parse_rsa_public_key(public_key)?;
        verify_rsa_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_saltlen,
            &evp_pkey,
            msg,
            signature,
            self.bit_size_range(),
        )
    }

    fn verify_digest_sig(
        &self,
        public_key: &[u8],
        digest: &Digest,
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = parse_rsa_public_key(public_key)?;
        verify_rsa_digest_signature(
            self.digest_algorithm(),
            self.padding(),
            self.pss_saltlen,
            &evp_pkey,
            digest,
            signature,
            self.bit_size_range(),
        )
    }
}

impl Sealed for RsaParameters {}

impl Debug for RsaParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{{ {:?} }}", self.verification_alg))
    }
}

impl RsaParameters {
    pub(crate) const fn new(
        digest_alg: &'static digest::Algorithm,
        padding: &'static RsaPadding,
        range: RangeInclusive<u32>,
        verification_alg: &'static RsaVerificationAlgorithmId,
    ) -> Self {
        Self {
            digest_alg,
            padding,
            range,
            verification_alg,
            pss_saltlen: None,
        }
    }

    /// Sets the PSS salt length to the given value.
    pub const fn with_pss_saltlen(mut self, saltlen: RsaPssSaltLength) -> Self {
        self.pss_saltlen = Some(saltlen);
        self
    }

    /// Parses a DER-encoded `RSAPublicKey` structure (RFC 8017) to determine its size in bits.
    ///
    /// # Errors
    /// `error::Unspecified` on parse error.
    pub fn public_modulus_len(public_key: &[u8]) -> Result<u32, Unspecified> {
        let rsa = encoding::rfc8017::decode_public_key_der(public_key)?;
        Ok(unsafe { RSA_bits(rsa.as_const().get_rsa()?.as_const_ptr()) })
    }

    #[must_use]
    /// Minimum modulus length in bits.
    pub fn min_modulus_len(&self) -> u32 {
        *self.range.start()
    }

    #[must_use]
    /// Maximum modulus length in bits.
    pub fn max_modulus_len(&self) -> u32 {
        *self.range.end()
    }
}

#[derive(Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub(crate) enum RsaVerificationAlgorithmId {
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub(crate) enum RsaSigningAlgorithmId {
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
}

#[allow(clippy::module_name_repetitions)]
/// Encoding type for an RSA signature
pub struct RsaSignatureEncoding {
    digest_alg: &'static digest::Algorithm,
    padding: &'static RsaPadding,
    pss_saltlen: Option<RsaPssSaltLength>,
    sig_alg: &'static RsaSigningAlgorithmId,
}

impl RsaSignatureEncoding {
    pub(crate) const fn new(
        digest_alg: &'static digest::Algorithm,
        padding: &'static RsaPadding,
        sig_alg: &'static RsaSigningAlgorithmId,
    ) -> Self {
        Self {
            digest_alg,
            padding,
            sig_alg,
            pss_saltlen: None,
        }
    }

    #[inline]
    pub(super) fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest_alg
    }

    #[inline]
    pub(super) fn padding(&self) -> &'static RsaPadding {
        self.padding
    }

    #[inline]
    pub(super) fn pss_saltlen(&self) -> Option<RsaPssSaltLength> {
        self.pss_saltlen
    }

    /// Sets the PSS salt length to the given value.
    pub const fn with_pss_saltlen(mut self, saltlen: RsaPssSaltLength) -> Self {
        self.pss_saltlen = Some(saltlen);
        self
    }
}

impl Sealed for RsaSignatureEncoding {}

/// An RSA signature encoding as described in [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
#[allow(clippy::module_name_repetitions)]
pub trait RsaEncoding: 'static + Sync + Sealed + Debug {
    /// The signature encoding.
    fn encoding(&'static self) -> &'static RsaSignatureEncoding;
}

impl RsaEncoding for RsaSignatureEncoding {
    fn encoding(&'static self) -> &'static RsaSignatureEncoding {
        self
    }
}

impl Debug for RsaSignatureEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("{{ {:?} }}", self.sig_alg))
    }
}

#[inline]
pub(crate) fn configure_rsa_pkcs1_pss_padding(
    pctx: *mut EVP_PKEY_CTX,
    saltlen: Option<RsaPssSaltLength>,
    algorithm: &'static digest::Algorithm,
    public_key: &LcPtr<EVP_PKEY>,
) -> Result<(), ()> {
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) } {
        return Err(());
    }

    let saltlen = saltlen
        .unwrap_or_default()
        .into_value(algorithm, public_key);

    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen) } {
        return Err(());
    }

    Ok(())
}

#[inline]
pub(crate) fn verify_rsa_signature(
    algorithm: &'static digest::Algorithm,
    padding: &'static RsaPadding,
    pss_saltlen: Option<RsaPssSaltLength>,
    public_key: &LcPtr<EVP_PKEY>,
    msg: &[u8],
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    if !allowed_bit_size.contains(&public_key.as_const().key_size_bits().try_into()?) {
        return Err(Unspecified);
    }

    let padding_fn = if let RsaPadding::RSA_PKCS1_PSS_PADDING = padding {
        Some(|pctx: *mut EVP_PKEY_CTX| {
            configure_rsa_pkcs1_pss_padding(pctx, pss_saltlen, algorithm, public_key)
        })
    } else {
        None
    };

    public_key.verify(msg, Some(algorithm), padding_fn, signature)
}

#[inline]
pub(crate) fn verify_rsa_digest_signature(
    algorithm: &'static digest::Algorithm,
    padding: &'static RsaPadding,
    pss_saltlen: Option<RsaPssSaltLength>,
    public_key: &LcPtr<EVP_PKEY>,
    digest: &Digest,
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    // Enforced here so no caller can omit it; the ctx below is configured from `digest`.
    if algorithm != digest.algorithm() {
        return Err(Unspecified);
    }

    if !allowed_bit_size.contains(&public_key.as_const().key_size_bits().try_into()?) {
        return Err(Unspecified);
    }

    let padding_fn = Some({
        |pctx: *mut EVP_PKEY_CTX| {
            let evp_md = match_digest_type(&digest.algorithm().id);
            if 1 != unsafe { EVP_PKEY_CTX_set_signature_md(pctx, evp_md.as_const_ptr()) } {
                return Err(());
            }
            if let RsaPadding::RSA_PKCS1_PSS_PADDING = padding {
                configure_rsa_pkcs1_pss_padding(pctx, pss_saltlen, algorithm, public_key)
            } else {
                Ok(())
            }
        }
    });

    public_key.verify_digest_sig(digest, padding_fn, signature)
}
