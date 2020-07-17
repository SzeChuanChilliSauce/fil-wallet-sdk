use std::slice::from_raw_parts;
use std::ffi::CStr;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::{Sha256, Digest};
use bls_signatures::{PrivateKey, Serialize};
use bip39::{Mnemonic, MnemonicType, Language};
use blake2b_simd::{Params};
use crate::bls::types;
use crate::bls::api::{PUBLIC_KEY_BYTES, PRIVATE_KEY_BYTES, fil_BLSPrivateKey};
use crate::bls::types::{fil_Address};
use crate::bls::utils::{fil_base32_encode};
use base64;
use std::ptr::slice_from_raw_parts;



const EXPORT_PRIVATE_KEY_BYTES: usize = 44;

/// Unwraps or returns the passed in value.
macro_rules! try_ffi {
    ($res:expr, $val:expr) => {{
        match $res {
            Ok(res) => res,
            Err(_) => return $val,
        }
    }};
}


/// 功  能: 创建BLS地址
///
/// 参  数:
///     net                 - 网络类型，'t'-测试网, 'f'-主网
///     proto               - 地址类型
///     raw_private_key_ptr - 私钥
///
/// 返回值: BLS地址
///
#[no_mangle]
pub unsafe extern "C" fn fil_private_key_to_bls_address(net: u8, proto: u8, raw_private_key_ptr: *const u8) -> *mut fil_Address {
    // 私钥生成公钥
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
    let private_key = try_ffi!(
        PrivateKey::from_bytes(private_key_slice),
        std::ptr::null_mut()
    );

    let mut raw_public_key: [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
    private_key
        .public_key()
        .write_bytes(&mut raw_public_key.as_mut())
        .expect("preallocated");

    // 网络号+公钥
    let mut protocol_pub_keys = [0u8;1+PUBLIC_KEY_BYTES];
    protocol_pub_keys[0] = proto;
    for i in 0..48 {
        protocol_pub_keys[i+1] = raw_public_key[i];
    };

    // 计算checksum
    let hash = Params::new()
        .hash_length(4)
        .to_state()
        .update(protocol_pub_keys.as_ref())
        .finalize();

    // 公钥+checksum
    let mut pubkey_checksum = [0u8;52];
    for i in 0..48 {
        pubkey_checksum[i] = raw_public_key[i];
    }
    for i in 0..4 {
        pubkey_checksum[48+i] = hash.as_bytes()[i];
    }

    // base32编码
    let res = fil_base32_encode(pubkey_checksum.as_ref());

    let mut addr :[u8;128] = [0u8;128];
    addr[0] = net;
    addr[1] = proto+48;
    for i in 0..res.len() {
        addr[2+i] = res[i];
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
/// 参  数: 无
///
/// 返回值: 钱包
///
#[no_mangle]
pub unsafe extern "C" fn fil_create_wallet() -> *mut types::fil_WalletResponse {
    // 生成种子和助记词
    let sm: (Vec<u8>, String) = seed_mnemonic();
    let entropy = sm.0;
    let words = sm.1;
    let bytes = words.as_bytes();
    let mut out :[u8;256] = [0u8;256];
    for i in 0..bytes.len() {
        out[i] = bytes[i];
    }

    // 计算种子哈希
    let mut hasher = Sha256::new();
    hasher.input(entropy);
    let res = hasher.result();

    let bytes = res.as_slice();
    let mut seed = types::fil_32ByteArray{
        inner: [0u8;32],
    };
    seed.inner[..bytes.len()].copy_from_slice(bytes);

    let rng = &mut ChaChaRng::from_seed(seed.inner);
    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(rng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

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
fn generate_private_key(raw_seed: types::fil_32ByteArray) -> *mut fil_BLSPrivateKey {
    let rng = &mut ChaChaRng::from_seed(raw_seed.inner);

    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(rng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

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
pub unsafe extern "C" fn fil_recovery_private_key(words_ptr: *const u8, count: usize) -> *mut fil_BLSPrivateKey {
    let bytes = from_raw_parts(words_ptr, count);
    let tmp = String::from_utf8(bytes.to_vec()).unwrap();
    let words = tmp.as_ref();

    // 检验助记词是否合法
    if Mnemonic::validate(words, Language::English).is_err() {
        println!("{}","invalid mnemonic");
        return std::ptr::null_mut()
    }

    // 根据助记词恢复种子
    let mnemonic = Mnemonic::from_phrase(words, Language::English).unwrap();
    let entropy = mnemonic.entropy();

    // 计算种子哈希
    let mut hasher = Sha256::new();
    hasher.input(entropy);
    let res = hasher.result();

    let bytes = res.as_slice();

    let mut seed = types::fil_32ByteArray{
        inner: [0u8;32],
    };
    seed.inner[..bytes.len()].copy_from_slice(bytes);

    generate_private_key(seed)
}

/// 功  能: 导出私钥
///
/// 参  数:
///     raw_private_key - 私钥
///
/// 返回值: 私钥导出结果
///
#[no_mangle]
pub unsafe extern "C" fn fil_export_private_key(raw_private_key: *const u8) -> *mut types::fil_ExportResult {
    let private_key_slice: &[u8] = from_raw_parts(raw_private_key, PRIVATE_KEY_BYTES);
    let private_key = try_ffi!(
        PrivateKey::from_bytes(private_key_slice),
        std::ptr::null_mut()
    );

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
    let mut decoded_bytes;
    match res {
        Ok(decoded) => {
            decoded_bytes = decoded;
        },
        Err(e) => {
            return  std::ptr::null_mut();
        }
    }

    let mut res: [u8;PRIVATE_KEY_BYTES] = [0u8;PRIVATE_KEY_BYTES];
    for i in 0..decoded_bytes.len() {
        res[i] = decoded_bytes[i];
    }

    let response = fil_BLSPrivateKey{
        inner: res,
    };

    Box::into_raw(Box::new(response))
}

