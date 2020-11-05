use std::slice::from_raw_parts;
use std::ffi::CStr;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::{Sha256, Digest};
use bls_signatures::{PrivateKey, Serialize, PublicKey};
use bip39::{Mnemonic, MnemonicType, Language};
use blake2b_simd::{Params};
use crate::bls::types;
use crate::bls::api::{PUBLIC_KEY_BYTES, PRIVATE_KEY_BYTES, fil_BLSPrivateKey};
use crate::bls::types::{fil_Address};
use crate::bls::utils::{fil_base32_encode};
use base64;
use std::ptr::slice_from_raw_parts;
use secp256k1::{Secp256k1,ContextFlag};
use secp256k1::key::{SecretKey, PublicKey as SecPublicKey};
use std::fmt::Error;


const EXPORT_PRIVATE_KEY_BYTES: usize = 44;
const CHECKSUM_HASH_LENGTH: usize = 4;
const PAYLOAD_HASH_LENGTH: usize = 20;

enum WalletError {
    RawPrivateKeyError,
    SecpPrivateKeyError,
    SecpPublicKeyError,

    GeneratePrivateKeyError,
}

/// Unwraps or returns the passed in value.
macro_rules! try_ffi {
    ($res:expr, $val:expr) => {{
        match $res {
            Ok(res) => res,
            Err(_) => return $val,
        }
    }};
}

/// 功  能: 生成BLS地址
///
/// 参  数:
///     proto - 地址类型: 1-secp256k1，3-bls
///
///     raw_private_key_ptr - 私钥
///
/// 返回值: bls地址
///
unsafe fn bls_address(proto: u8, raw_private_key_ptr: *const u8) -> Result<Vec<u8>, WalletError> {
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);

    let raw_key = PrivateKey::from_bytes(private_key_slice);
    if raw_key.is_err() {
        return Err(WalletError::RawPrivateKeyError);
    }
    let private_key = raw_key.unwrap();

    let mut raw_public_key: [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
    private_key
        .public_key()
        .write_bytes(&mut raw_public_key.as_mut())
        .expect("preallocated");

    // 算法类型+公钥
    let mut protocol_pub_keys = [0u8;1+PUBLIC_KEY_BYTES];
    protocol_pub_keys[0] = proto;
    for i in 0..PUBLIC_KEY_BYTES {
        protocol_pub_keys[i+1] = raw_public_key[i];
    };

    // 计算checksum
    let hash = Params::new()
        .hash_length(CHECKSUM_HASH_LENGTH)
        .to_state()
        .update(protocol_pub_keys.as_ref())
        .finalize();

    // 公钥+checksum
    let mut pubkey_checksum = [0u8;CHECKSUM_HASH_LENGTH+PUBLIC_KEY_BYTES];
    for i in 0..PUBLIC_KEY_BYTES {
        pubkey_checksum[i] = raw_public_key[i];
    }
    for i in 0..CHECKSUM_HASH_LENGTH {
        pubkey_checksum[PUBLIC_KEY_BYTES+i] = hash.as_bytes()[i];
    }

    // base32编码
    let res = fil_base32_encode(pubkey_checksum.as_ref());
    Ok(res)
}

/// 功  能: 生成secp256k1地址
///
/// 参  数:
///     proto - 地址类型: 1 - secp256k1，3 - bls
///
///     raw_private_key_ptr - 私钥
///
/// 返回值: bls地址
///
unsafe fn secp256k1_address(proto: u8, raw_private_key_ptr: *const u8) -> Result<Vec<u8>, WalletError> {
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);

    // 私钥
    let none = Secp256k1::with_caps(ContextFlag::None);
    let sk_res = SecretKey::from_slice(&none, private_key_slice);
    if sk_res.is_err() {
        return Err(WalletError::SecpPrivateKeyError)
    }
    let sk = sk_res.unwrap();

    // 公钥
    let secp = Secp256k1::new();
    let pk_res = SecPublicKey::from_secret_key(&secp, &sk);
    if pk_res.is_err() {
        return Err(WalletError::SecpPublicKeyError);
    }
    let pk = pk_res.unwrap();
    let pk_vec: Vec<u8> = pk.serialize_vec(&secp, false).to_vec();

    // payload
    let payload = Params::new()
        .hash_length(PAYLOAD_HASH_LENGTH)
        .to_state()
        .update(pk_vec.as_slice())
        .finalize();

    // proto+payload
    let mut proto_payload = [0u8;1+PAYLOAD_HASH_LENGTH];
    proto_payload[0] = proto;
    for i in 0..PAYLOAD_HASH_LENGTH {
        proto_payload[i+1] = payload.as_bytes()[i];
    }

    // checksum
    let cheksum = Params::new()
        .hash_length(CHECKSUM_HASH_LENGTH)
        .to_state()
        .update( proto_payload.as_ref())
        .finalize();

    // 算法类型+公钥
    let mut payload_checksum = [0u8; PAYLOAD_HASH_LENGTH+CHECKSUM_HASH_LENGTH];
    for i in 0..PAYLOAD_HASH_LENGTH {
        payload_checksum[i] = payload.as_bytes()[i];
    }
    for i in 0..CHECKSUM_HASH_LENGTH {
        payload_checksum[i+PAYLOAD_HASH_LENGTH] = cheksum.as_bytes()[i];
    }

    // base32编码
    let res = fil_base32_encode(payload_checksum.as_ref());
    Ok(res)
}

/// 功  能: 私钥生成地址
///
/// 参  数:
///     net - 网络类型: 't'-测试网, 'f'-主网
///
///     proto - 地址类型: 1-secp256k1, 3-bls
///
///     raw_private_key_ptr - 私钥
///
/// 返回值: 地址
///
#[no_mangle]
pub unsafe extern "C" fn fil_private_key_to_address(net: u8, proto: u8, raw_private_key_ptr: *const u8) -> *mut fil_Address {
    let mut addr :[u8;128] = [0u8;128];
    addr[0] = net;
    addr[1] = proto+48;

    match proto {
        1 => {
            let res = secp256k1_address(proto, raw_private_key_ptr);
            if res.is_err() {
                return std::ptr::null_mut();
            }
            let data = res.unwrap_or_default();
            for i in 0..data.len() {
                addr[2+i] = data[i];
            }
        }

        3 => {
            let res = bls_address(proto, raw_private_key_ptr);
            if res.is_err() {
                return std::ptr::null_mut();
            }
            let data = res.unwrap_or_default();
            for i in 0..data.len() {
                addr[2+i] = data[i];
            }
        }

        _ => { // 错误类型
            return std::ptr::null_mut()
        }
    }

    let response = fil_Address{
        network: net,
        protocol: proto,
        address: addr,
    };

    Box::into_raw(Box::new(response))
}

/// 功  能: 创建钱包
///
/// 参  数: typ - 地址类型:
///              1 - secp256k1
///              3 - bls
///
/// 返回值: 钱包
///
#[no_mangle]
pub unsafe extern "C" fn fil_create_wallet(typ: u8) -> *mut types::fil_WalletResponse {
    // 生成种子和助记词
    let sm: (Vec<u8>, String) = seed_mnemonic();
    let words_bytes = sm.1.as_bytes();
    let mut out: [u8;256] = [0u8;256];
    for i in 0..words_bytes.len() {
        out[i] = words_bytes[i];
    }

    // 计算种子哈希
    let mut hasher = Sha256::new();
    hasher.input(sm.0);
    let res = hasher.result();
    let hash_bytes = res.as_slice();
    let mut seed = types::fil_32ByteArray{
        inner: [0u8;32],
    };
    seed.inner.copy_from_slice(hash_bytes);

    let mut rng = &mut ChaChaRng::from_seed(seed.inner);
    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    match typ {
        1 => {
            let secp = Secp256k1::new();
            let res = secp.generate_keypair(&mut rng);
            if res.is_err() {
                return std::ptr::null_mut();
            }
            let (sk, _) = res.unwrap();
            for i in 0..PRIVATE_KEY_BYTES {
                raw_private_key[i] = sk[i];
            }
        }

        3 => {
            PrivateKey::generate(rng)
                .write_bytes(&mut raw_private_key.as_mut())
                .expect("preallocated");
        }

        _ => {
            return std::ptr::null_mut();
        }
    }


    let response = types::fil_WalletResponse{
        private_key: fil_BLSPrivateKey{
            inner: raw_private_key,
        },
        mnemonic: out,
    };

    Box::into_raw(Box::new(response))
}

/// 功  能: 生成助记词和随机种子
///
/// 参  数: 无
///
/// 返回值:
///     entropy - 助记词的熵
///     words   - 助记词
///
#[no_mangle]
fn seed_mnemonic() -> (Vec<u8>, String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = String::from(mnemonic.phrase());
    let entropy = mnemonic.entropy();
    (entropy.to_vec(), phrase)
}

/// 功  能: 根据种子生成私钥
///
/// 参  数:
///     raw_seed - 用于生成私钥的种子
///
/// 返回值: 私钥
///
#[no_mangle]
fn generate_private_key(typ: u8, raw_seed: types::fil_32ByteArray) -> *mut fil_BLSPrivateKey {
    let mut rng = &mut ChaChaRng::from_seed(raw_seed.inner);

    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];

    match typ {
        1 => {
            let secp = Secp256k1::new();
            let res = secp.generate_keypair(&mut rng);
            if res.is_err() {
                return std::ptr::null_mut();
            }
            let (sk, _) = res.unwrap();
            for i in 0..PRIVATE_KEY_BYTES {
                raw_private_key[i] = sk[i];
            }
        }

        3 => {
            PrivateKey::generate(rng)
                .write_bytes(&mut raw_private_key.as_mut())
                .expect("preallocated");
        }

        _ => {
            return std::ptr::null_mut();
        }
    }

    let response = fil_BLSPrivateKey {
        inner: raw_private_key,
    };

    Box::into_raw(Box::new(response))
}

/// 功  能: 根据助记词字符串恢复私钥
///
/// 参  数:
///     words_ptr - 助记词字符串
///     count - 助记词字符串长度
///
/// 返回值: 私钥
///
#[no_mangle]
pub unsafe extern "C" fn fil_recover_private_key(typ: u8, words_ptr: *const u8, count: usize) -> *mut fil_BLSPrivateKey {
    let bytes = from_raw_parts(words_ptr, count);
    let tmp = String::from_utf8(bytes.to_vec()).unwrap();
    let words = tmp.as_ref();

    // 检验助记词是否合法
    if Mnemonic::validate(words, Language::English).is_err() {
        return std::ptr::null_mut()
    }

    // 根据助记词恢复种子
    let res = Mnemonic::from_phrase(words, Language::English);
    if res.is_err() {
        return std::ptr::null_mut();
    }
    let mnemonic = res.unwrap();
    let entropy = mnemonic.entropy();

    // 计算种子哈希
    let mut hasher = Sha256::new();
    hasher.input(entropy);
    let res = hasher.result();

    let bytes = res.as_slice();

    let mut seed = types::fil_32ByteArray{
        inner: [0u8;PRIVATE_KEY_BYTES],
    };
    seed.inner.copy_from_slice(bytes);

    generate_private_key(typ,seed)
}

/// 功  能: 导出私钥
///
/// 参  数:
///     raw_private_key - 私钥
///
/// 返回值: 私钥导出结果
///
#[no_mangle]
pub unsafe extern "C" fn fil_export_private_key(typ: u8, raw_private_key: *const u8) -> *mut types::fil_ExportResult {
    let private_key_slice: &[u8] = from_raw_parts(raw_private_key, PRIVATE_KEY_BYTES);

    match typ {
        3 => {
            // 校验bls私钥
            let _ = try_ffi!(
                PrivateKey::from_bytes(private_key_slice),
                std::ptr::null_mut()
            );
        }
        _ => {}
    }

    let encoded = base64::encode(private_key_slice);
    let encoded_bytes = encoded.as_bytes();

    let mut raw_bytes: [u8;44]  = [0u8;44];
    for i in 0..encoded_bytes.len() {
        raw_bytes[i] = encoded_bytes[i];
    }

    let response = types::fil_ExportResult{
        inner: raw_bytes,
    };

    Box::into_raw(Box::new(response))
}

/// 功  能: 导入私钥
///
/// 参  数:
///     raw_bytes - 私钥明文
///
/// 返回值: 私钥
///
#[no_mangle]
pub unsafe extern "C" fn fil_import_private_key(raw_bytes: *const u8) -> *mut fil_BLSPrivateKey {
    let input: &[u8] = from_raw_parts(raw_bytes, EXPORT_PRIVATE_KEY_BYTES);

    let res = base64::decode(input);
    if res.is_err() {
        return std::ptr::null_mut();
    }

    let mut sk= [0u8;PRIVATE_KEY_BYTES];
    let decoded_bytes = res.unwrap();
    let l = decoded_bytes.len();
    if l > PRIVATE_KEY_BYTES {
        return std::ptr::null_mut();
    }
    for i in 0..l {
        sk[i] = decoded_bytes[i];
    }

    let response = fil_BLSPrivateKey{
        inner: sk,
    };

    Box::into_raw(Box::new(response))
}

