use crate::core::jwk::CoreJsonCurveType;
use crate::core::{CoreJsonWebKey, CoreJsonWebKeyType};
use crate::helpers::Base64UrlEncodedBytes;
use crate::{JsonWebKey, SignatureVerificationError};

use std::ops::Deref;

fn rsa_public_key(
    key: &CoreJsonWebKey,
) -> Result<(&Base64UrlEncodedBytes, &Base64UrlEncodedBytes), String> {
    if *key.key_type() != CoreJsonWebKeyType::RSA {
        Err("RSA key required".to_string())
    } else {
        let n = key
            .n
            .as_ref()
            .ok_or_else(|| "RSA modulus `n` is missing".to_string())?;
        let e = key
            .e
            .as_ref()
            .ok_or_else(|| "RSA exponent `e` is missing".to_string())?;
        Ok((n, e))
    }
}

fn ec_public_key(
    key: &CoreJsonWebKey,
) -> Result<
    (
        &Base64UrlEncodedBytes,
        &Base64UrlEncodedBytes,
        &CoreJsonCurveType,
    ),
    String,
> {
    if *key.key_type() != CoreJsonWebKeyType::EllipticCurve {
        Err("EC key required".to_string())
    } else {
        let x = key
            .x
            .as_ref()
            .ok_or_else(|| "EC `x` part is missing".to_string())?;
        let y = key
            .y
            .as_ref()
            .ok_or_else(|| "EC `y` part is missing".to_string())?;
        let crv = key
            .crv
            .as_ref()
            .ok_or_else(|| "EC `crv` part is missing".to_string())?;
        Ok((x, y, crv))
    }
}

fn ed_public_key(
    key: &CoreJsonWebKey,
) -> Result<(&Base64UrlEncodedBytes, &CoreJsonCurveType), String> {
    if *key.key_type() != CoreJsonWebKeyType::OctetKeyPair {
        Err("OKP key required".to_string())
    } else {
        let x = key
            .x
            .as_ref()
            .ok_or_else(|| "OKP `x` part is missing".to_string())?;
        let crv = key
            .crv
            .as_ref()
            .ok_or_else(|| "OKP `crv` part is missing".to_string())?;
        Ok((x, crv))
    }
}

pub fn verify_rsa_signature(
    key: &CoreJsonWebKey,
    padding: impl rsa::traits::SignatureScheme,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    let (n, e) = rsa_public_key(key).map_err(SignatureVerificationError::InvalidKey)?;
    // let's n and e as a big integers to prevent issues with leading zeros
    // according to https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1
    // `n` is always unsigned (hence has sign plus)

    let n_bigint = rsa::BoxedUint::from_be_slice_vartime(n.deref());
    let e_bigint = rsa::BoxedUint::from_be_slice_vartime(e.deref());
    let public_key = rsa::RsaPublicKey::new(n_bigint, e_bigint)
        .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;

    public_key
        .verify(padding, msg, signature)
        .map_err(|_| SignatureVerificationError::CryptoError("bad signature".to_string()))
}

/// According to RFC5480, Section-2.2 implementations of Elliptic Curve Cryptography MUST support the uncompressed form.
/// The first octet of the octet string indicates whether the uncompressed or compressed form is used. For the uncompressed
/// form, the first octet has to be 0x04.
/// According to https://briansmith.org/rustdoc/ring/signature/index.html#ecdsa__fixed-details-fixed-length-pkcs11-style-ecdsa-signatures,
/// to recover the X and Y coordinates from an octet string, the Octet-String-To-Elliptic-Curve-Point Conversion
/// is used (Section 2.3.4 of https://www.secg.org/sec1-v2.pdf).
pub fn verify_ec_signature(
    key: &CoreJsonWebKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    use p256::ecdsa::signature::Verifier;

    let (x, y, crv) = ec_public_key(key).map_err(SignatureVerificationError::InvalidKey)?;
    let mut pk = vec![0x04];
    pk.extend(x.deref());
    pk.extend(y.deref());
    match *crv {
        CoreJsonCurveType::P256 => {
            let public_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk)
                .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;
            public_key
                .verify(
                    msg,
                    &p256::ecdsa::Signature::from_slice(signature).map_err(|_| {
                        SignatureVerificationError::CryptoError("Invalid signature".to_string())
                    })?,
                )
                .map_err(|_| {
                    SignatureVerificationError::CryptoError("EC Signature was wrong".to_string())
                })
        }
        CoreJsonCurveType::P384 => {
            let public_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&pk)
                .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;
            public_key
                .verify(
                    msg,
                    &p384::ecdsa::Signature::from_slice(signature).map_err(|_| {
                        SignatureVerificationError::CryptoError("Invalid signature".to_string())
                    })?,
                )
                .map_err(|_| {
                    SignatureVerificationError::CryptoError("EC Signature was wrong".to_string())
                })
        }
        CoreJsonCurveType::P521 => Err(SignatureVerificationError::UnsupportedAlg(
            "P521".to_string(),
        )),
        _ => Err(SignatureVerificationError::InvalidKey(format!(
            "unrecognized curve `{crv:?}`"
        ))),
    }
}

pub fn verify_ed_signature(
    key: &CoreJsonWebKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureVerificationError> {
    use ed25519_dalek::Verifier;

    let (x, crv) = ed_public_key(key).map_err(SignatureVerificationError::InvalidKey)?;

    match *crv {
        CoreJsonCurveType::Ed25519 => {
            let public_key = ed25519_dalek::VerifyingKey::try_from(x.deref().as_slice())
                .map_err(|e| SignatureVerificationError::InvalidKey(e.to_string()))?;

            public_key
                .verify(
                    msg,
                    &ed25519_dalek::Signature::from_slice(signature).map_err(|_| {
                        SignatureVerificationError::CryptoError("invalid signature".to_string())
                    })?,
                )
                .map_err(|_| {
                    SignatureVerificationError::CryptoError("incorrect EdDSA signature".to_string())
                })
        }
        _ => Err(SignatureVerificationError::InvalidKey(format!(
            "unrecognized curve `{crv:?}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::verify_rsa_signature;
    use crate::core::CoreJsonWebKey;

    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::Digest;

    #[test]
    fn test_leading_zeros_are_parsed_correctly() {
        // The message we signed
        let msg = "THIS IS A SIGNATURE TEST";
        let signature = BASE64_URL_SAFE_NO_PAD.decode("XxaCBk7XK1BLW-n-SNFqiVXaL3_Aid80VWspX8dPcDTSe59qq6-miOAO1B-FGXzt6v8bseMxuagjZ0JSy3Z-NvEZMHIxCiP-9HZK2SKTTA4ediOd4HzNjICeWftGL1bYLoXHOnhZ0ZjkpNKur69Sz76Uf61IfAKB2sWwXLvop5oLhuAm5THQMguSrcQ-rcOlmWjNvl1eMiBPSrhxCrsUsu0QE5RcgmUbKq85UT5eX0R6fIQeta4w-lHvqJqCymCsMpxbCE-kvHN1ckjntJqmWxDqVTbgbJqxXDFBqSNnZZpetAdIR4opxYWvcxJwaIlopGedmT7l7s7AOT3nFVQ").unwrap();
        // RSA public key (2032-bit modulus) whose `n` is zero-padded to 256 bytes
        let key : CoreJsonWebKey = serde_json::from_value(serde_json::json!(
            {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "TEST_KEY_ID",
            "alg": "RS256",
            "n": "AADKbjFZkhSGtn89Cj5QdWpbclLeEklfP1TRbuWVvE0KTYSSy_8_S0YvyKADYZypwbIZpcmMJ133yCUq4qnVA1C3O4JUVeCKGlHr0PdF0FSmkZlzL2bFS5ZpJILFcl_qxmDGelz3K4ZYpqwscIKufgYK3K5icXl3Tcxor6FTnJPudzlp2m8Ncmge4gfoBI3DwWLJxrp3P1QhFh4Y2P6skFGlQlTP1xYsBxSZHSUDAFrVbh358ycFIbymZKAU4HLZS0O73xKIAiOov_F8t9H5u7xrvlQ5uc3fTVGnqbtTwCkVCfVgl87lPFySbUnmKI01m9rRp4Y-WLloYLjn_e9eyQ"
            }
        )).unwrap();

        let mut hasher = sha2::Sha256::new();
        hasher.update(msg);
        let hash = hasher.finalize().to_vec();
        assert! {
            verify_rsa_signature(
                &key,
                rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                &hash,
                &signature,
            ).is_ok()
        }
    }
}
