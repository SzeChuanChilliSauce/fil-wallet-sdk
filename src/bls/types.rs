use crate::bls::api::{fil_BLSDigest, fil_BLSPrivateKey, fil_BLSPublicKey, fil_BLSSignature};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fil_32ByteArray {
    pub inner: [u8; 32],
}

/// HashResponse

#[repr(C)]
pub struct fil_HashResponse {
    pub digest: fil_BLSDigest,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_hash_response(ptr: *mut fil_HashResponse) {
    let _ = Box::from_raw(ptr);
}

/// AggregateResponse

#[repr(C)]
pub struct fil_AggregateResponse {
    pub signature: fil_BLSSignature,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_aggregate_response(ptr: *mut fil_AggregateResponse) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeyGenerateResponse

#[repr(C)]
pub struct fil_PrivateKeyGenerateResponse {
    pub private_key: fil_BLSPrivateKey,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_generate_response(ptr: *mut fil_PrivateKeyGenerateResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_bls_private_key(ptr: *mut fil_BLSPrivateKey) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeySignResponse

#[repr(C)]
pub struct fil_PrivateKeySignResponse {
    pub signature: fil_BLSSignature,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_sign_response(ptr: *mut fil_PrivateKeySignResponse) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeyPublicKeyResponse

#[repr(C)]
pub struct fil_PrivateKeyPublicKeyResponse {
    pub public_key: fil_BLSPublicKey,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_public_key_response(ptr: *mut fil_PrivateKeyPublicKeyResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub struct fil_WalletResponse {
    pub private_key: fil_BLSPrivateKey,
    pub mnemonic:[u8;256],
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_wallet(ptr: *mut fil_WalletResponse) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub struct fil_Address {
    pub network: u8,
    pub protocol: u8,
    pub address: [u8;128],
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_address(ptr:*mut fil_Address) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub struct fil_ExportResult {
    pub inner: [u8;44],
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_export_result(ptr: *mut fil_ExportResult) {
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub struct fil_SignedMessageResult {
    pub cid: [u8;62],
    pub secp_sig: [u8;65],
    pub bls_sig: [u8;96],
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_signed_message(ptr: *mut fil_SignedMessageResult) {
    let _ = Box::from_raw(ptr);
}

