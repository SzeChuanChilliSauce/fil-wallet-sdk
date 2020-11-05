use std::slice::from_raw_parts;
use num_bigint::{BigInt, Sign};
use crate::bls::api::{fil_BLSSignature, SIGNATURE_BYTES, PRIVATE_KEY_BYTES, PUBLIC_KEY_BYTES};

use crate::bls::utils::{V1Builder, DAG_CBOR, BLAKE2B_256, DEFAULT_LENGTH, fil_base32_decode, fil_base32_encode};
use crate::bls::{utils, types};
use bls_signatures::{PrivateKey, Serialize};
use std::borrow::Borrow;
use secp256k1::{Secp256k1,ContextFlag, Message};
use secp256k1::key::{SecretKey as SecpPrivateKey, PublicKey as SecPublicKey};
use blake2b_simd::{Params};


const SECP_SIGNATURE_BYTES: usize = 64;
const SECP_HASH_BYTES: usize = 32;

/// major types
const MAJ_UNSIGNED_INT: u8 = 0;
const MAJ_NEGATIVE_INT: u8 = 1;
const MAJ_BYTE_STRING:  u8 = 2;
const MAJ_TEXT_STRING:  u8 = 3;
const MAJ_ARRAY:        u8 = 4;
const MAJ_MAP:          u8 = 5;
const MAJ_TAG:          u8 = 6;
const MAJ_OTHER:        u8 = 7;

const LENGTH_BUF_MESSAGE: u8 = 138;

/// filecoin交易（消息）
pub struct FilMessage {
    pub version: i64,
    pub to: String,
    pub from: String,
    pub nonce: u64,
    pub value: BigInt,
    pub gas_fee_cap: BigInt,
    pub gas_premium: BigInt,
    pub gas_limit: i64,
    pub method: u64,
    pub params: Vec<u8>,
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

impl FilMessage {

    /// 序列化交易
    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(LENGTH_BUF_MESSAGE);
        self.marshal_cbor(&mut buf);
        buf
    }

    /// 序列化为简明二进制对象格式的数据
    fn marshal_cbor(&self, buf: &mut Vec<u8>) {
        let mut scratch = vec![0u8; 9];

        // version
        if self.version >= 0 {
            write_major_type_header_buf(scratch.as_mut(), buf, MAJ_UNSIGNED_INT, self.version as u64);
        } else {
            write_major_type_header_buf(scratch.as_mut(), buf, MAJ_NEGATIVE_INT, (-self.version-1) as u64);
        }

        // address
        marshal_cbor_address(buf, self.to.as_ref());
        marshal_cbor_address(buf, self.from.as_ref());

        // nonce
        write_major_type_header_buf(scratch.as_mut(), buf, MAJ_UNSIGNED_INT, self.nonce);

        // value
        marshal_cbor_bigint(buf, &self.value);

        // gas limit
        if self.gas_limit >= 0 {
            write_major_type_header_buf(scratch.as_mut(), buf, MAJ_UNSIGNED_INT, self.gas_limit as u64);
        } else {
            write_major_type_header_buf(scratch.as_mut(), buf, MAJ_NEGATIVE_INT, (-self.gas_limit-1) as u64)
        }

        // GasFeeCap
        marshal_cbor_bigint(buf, &self.gas_fee_cap);

        // GasPremium
        marshal_cbor_bigint(buf, &self.gas_premium);

        // method
        write_major_type_header_buf(scratch.as_mut(), buf, MAJ_UNSIGNED_INT, self.method);

        // params len
        write_major_type_header_buf(scratch.as_mut(), buf, MAJ_BYTE_STRING, self.params.len() as u64);

        // params
        for i in 0..self.params.len() {
            buf.push(self.params[i]);
        }
    }

}

/// 功  能: 签名交易
///
/// 参  数:
///     typ             - 私钥类型
///     raw_private_key - 私钥
///     version         - 交易版本号
///     nonce           - 交易序号
///     method          - 交易方法号
///     to              - 收款人地址
///     to_len          - 收款人地址长度
///     from            - 付款人地址
///     from_len        - 付款人地址长度
///     value           - 金额
///     value           - 金额长度
///     gas_premium     - 油价
///     gas_premium_len - 油价字长度
///     gas_fee_cap     - 油价上限
///     gas_fee_cap_len - 油价上限长度
///     gas_limit       - 油量上限
///     params          - 交易携带数据
///     params_len      - 交易携带数据长度
/// 返回值: 交易的签名
///
#[no_mangle]
pub unsafe extern "C" fn sign_transaction_message(typ: u8, raw_private_key: *const u8,
                                                  version: i64,
                                                  nonce: u64,
                                                  method: u64,
                                                  to: *const u8,
                                                  to_len: usize,
                                                  from: *const u8,
                                                  from_len: usize,
                                                  value: *const u8,
                                                  value_len: usize,
                                                  gas_premium: *const u8,
                                                  gas_premium_len: usize,
                                                  gas_fee_cap: *const u8,
                                                  gas_fee_cap_len: usize,
                                                  gas_limit: i64,
                                                  params: *const u8,
                                                  params_len: usize) ->*mut types::fil_SignedMessageResult {
    // 获取私钥
    let private_key_slice = from_raw_parts(raw_private_key, PRIVATE_KEY_BYTES);

    // To
    let to_addr_bytes = from_raw_parts(to, to_len);
    let to_str = String::from_utf8(to_addr_bytes.to_vec()).unwrap();

    // From
    let from_addr_bytes = from_raw_parts(from, from_len);
    let from_str = String::from_utf8(from_addr_bytes.to_vec()).unwrap();

    // Value
    let value_bytes = from_raw_parts(value, value_len);

    // GasFeeCap
    let gas_fee_cap_bytes = from_raw_parts(gas_fee_cap, gas_fee_cap_len);

    // GasPremium
    let gas_premium_bytes = from_raw_parts(gas_premium, gas_premium_len);

    // Params
    let mut params_bytes = vec![];
    if params != std::ptr::null() {
        let bytes = from_raw_parts(params, params_len);
        params_bytes = Vec::from(bytes);
    }

    // 将value转为BigInt
    let mut big_val = BigInt::default();
    let op_val = BigInt::parse_bytes(value_bytes, 10);
    if let Some(val) = op_val {
        big_val = val;
    } else {
        return  std::ptr::null_mut();
    }

    // 将GasFeeCap转为BigInt
    let mut big_gas_fee_cap = BigInt::default();
    let op_gas_fee_cap = BigInt::parse_bytes(gas_fee_cap_bytes, 10);
    if let Some(v) = op_gas_fee_cap {
        big_gas_fee_cap = v;
    } else {
        return  std::ptr::null_mut();
    }

    // 将GasPremium转为BigInt
    let mut big_gas_premium = BigInt::default();
    let op_gas_premium = BigInt::parse_bytes(gas_premium_bytes, 10);
    if let Some(v) = op_gas_premium {
        big_gas_premium = v;
    } else {
        return std::ptr::null_mut();
    }

    // 构造交易
    let tx = FilMessage{
        version,
        to:   to_str,
        from: from_str,
        nonce,
        value: big_val,
        gas_fee_cap: big_gas_fee_cap,
        gas_premium: big_gas_premium,
        gas_limit,
        method,
        params: Vec::from(params_bytes),
    };

    // 序列化
    let mut serialized_data = tx.serialize();

    //println!("serialized = {:?}", serialized_data);

    let v1 = V1Builder {
        codec: DAG_CBOR,
        mh_type: BLAKE2B_256,
        mh_length: DEFAULT_LENGTH[&BLAKE2B_256],
    };

    // cid
    let cid = v1.sum(serialized_data.as_mut());
    let cid_bak = cid.clone();

    // base32编码
    let enc_cid_bytes = fil_base32_encode(cid_bak.as_ref());

    let mut cid_with_prefix: Vec<u8> = Vec::new();
    // 加前缀:'b'
    cid_with_prefix.push(b'b');
    // 拷贝
    for i in 0..enc_cid_bytes.len() {
        cid_with_prefix.push(enc_cid_bytes[i]);
    }
    let mut cid_bytes = [0u8;62];
    for i in 0..cid_with_prefix.len(){
        cid_bytes[i] = cid_with_prefix[i];
    }

    match typ {
        1 => {
            let secp = Secp256k1::new();
            let res = SecpPrivateKey::from_slice(&secp, private_key_slice);
            if res.is_err() {
                return std::ptr::null_mut();
            }
            let sk = res.unwrap();

            // 计算cid哈希
            let cid_hash = Params::new()
                .hash_length(SECP_HASH_BYTES)
                .to_state()
                .update( cid.as_ref())
                .finalize();

            let msg_res = Message::from_slice(cid_hash.as_ref());
            if msg_res.is_err() {
                return std::ptr::null_mut();
            }
            let msg = msg_res.unwrap();

            let mut raw_secp_sig = [0; SECP_SIGNATURE_BYTES+1];

            // 签名 - RFC6979
            let sig_res = secp.sign_recoverable(&msg, &sk);
            if sig_res.is_err() {
                return std::ptr::null_mut();
            }
            let sig = sig_res.unwrap();

            // recovery id and signature
            let (id, bytes) = sig.serialize_compact(&secp);

            // 前64字节为签名数据，最后一位为recovery id
            for i in 0..SECP_SIGNATURE_BYTES {
                raw_secp_sig[i] = bytes[i];
            }
            raw_secp_sig[SECP_SIGNATURE_BYTES] = id.to_i32() as u8;

            let response = types::fil_SignedMessageResult{
                cid: cid_bytes,
                secp_sig: raw_secp_sig,
                bls_sig: [0u8;96],
            };

            Box::into_raw(Box::new(response))
        }

        3 => {
            let private_key = try_ffi!(
                PrivateKey::from_bytes(private_key_slice),
                std::ptr::null_mut()
            );

            let mut raw_bls_sig: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];

            // 签名cid
            PrivateKey::sign(&private_key, cid)
                .write_bytes(&mut raw_bls_sig.as_mut())
                .expect("preallocated");

            let response = types::fil_SignedMessageResult{
                cid: cid_bytes,
                secp_sig: [0u8;65],
                bls_sig: raw_bls_sig,
            };

            Box::into_raw(Box::new(response))
        }

        _ => {
            return std::ptr::null_mut();
        }
    }
}

/// 功  能: 序列化地址
///
/// 参  数:
///     buf  - 存放序列化后数据的数组
///     addr - 地址
///
/// 返回值: 无
///
fn marshal_cbor_address(buf: &mut Vec<u8>, addr: &str) {
    // 获取地址类型
    let addr_type: u8 = addr.as_bytes()[1] - 48;

    // 从地址的第3个字符开始，解码地址，获得公钥和checksum
    let bytes: &str = addr[2..].as_ref();
    let decoded = fil_base32_decode(bytes);
    let pub_key_checksum = decoded.as_slice();

    // 地址类型和公钥
    let mut addr_type_pub_key:Vec<u8> = Vec::new();
    addr_type_pub_key.push(addr_type);
    for i in 0..(pub_key_checksum.len()-4) {
        addr_type_pub_key.push(pub_key_checksum[i]);
    }

    // 地址长度
    write_major_type_header(buf, MAJ_BYTE_STRING, addr_type_pub_key.len() as u64);

    // 地址
    for i in 0..addr_type_pub_key.len() {
        buf.push(addr_type_pub_key[i]);
    }
}

/// 功  能: 序列化big int
///
/// 参  数:
///     buf - 存放序列化后数据的数组
///     num - 大数
///
/// 返回值:
///
fn marshal_cbor_bigint(buf: &mut Vec<u8>, num: &BigInt) {
    if num.eq(&BigInt::from(0)) {
        let header = cbor_encode_major_type(MAJ_BYTE_STRING, 0);
        for i in 0..header.len() {
            buf.push(header[i]);
        }
        return
    }

    let num_bytes = num.to_signed_bytes_be();

    if num_bytes[0] != 0 {
        let mut enc = vec![0u8;num_bytes.len()+1];
        enc[0] = 0;
        for i in 0..num_bytes.len() {
            enc[i+1] = num_bytes[i];
        }
        let header = cbor_encode_major_type(MAJ_BYTE_STRING, enc.len() as u64);
        for i in 0..header.len() {
            buf.push(header[i]);
        }
        for i in 0.. enc.len() {
            buf.push(enc[i]);
        }
    } else {
        let header = cbor_encode_major_type(MAJ_BYTE_STRING, num_bytes.len() as u64);
        for i in 0..header.len() {
            buf.push(header[i]);
        }
        for i in 0.. num_bytes.len() {
            buf.push(num_bytes[i]);
        }
    }
}

/// 功  能: 序列化类型
///
/// 参  数:
///     buf - 存放序列化后数据的数组
///     t   - 类型
///     l   - 长度
///
/// 返回值: 无
///
fn write_major_type_header(buf: &mut Vec<u8>, t: u8, l: u64) {
    if l < 24 {
        buf.push((t << 5) | (l as u8));
    } else if l < (1 << 8) {
        buf.push((t << 5) | 24);
        buf.push(l as u8);
    } else if l < (1 << 16) {
        buf.push((t << 5) | 25);
        let n = l as u16;
        buf.push(((n >> 8) & 0xFF) as u8);
        buf.push((n & 0xFF) as u8);
    } else if l < (1 << 32) {
        buf.push((t << 5) | 26);
        let n = l as u32;
        buf.push(((n >> 24) & 0xFF) as u8);
        buf.push(((n >> 16) & 0xFF) as u8);
        buf.push(((n >> 8) & 0xFF) as u8);
        buf.push((n & 0xFF) as u8);
    } else {
        buf.push((t << 5) | 27);
        let n = l as u64;
        buf.push(((n >> 56) & 0xFF) as u8);
        buf.push(((n >> 58) & 0xFF) as u8);
        buf.push(((n >> 40) & 0xFF) as u8);
        buf.push(((n >> 32) & 0xFF) as u8);
        buf.push(((n >> 24) & 0xFF) as u8);
        buf.push(((n >> 16) & 0xFF) as u8);
        buf.push(((n >> 8) & 0xFF) as u8);
        buf.push((n & 0xFF) as u8);
    }
}

/// 功  能: 序列化类型（带外部缓冲区数据）
///
/// 参  数:
///     scratch - 外部数据
///     buf     - 存放序列化后数据的数组
///     t       - 类型
///     l       - 长度
///
/// 返回值: 无
///
fn write_major_type_header_buf(scratch: &mut Vec<u8>, buf: &mut Vec<u8>, t: u8, l: u64) {
    if l < 24 {
        scratch[0] = (t << 5) | (l as u8);
        buf.push(scratch[0]);
    } else if l < (1 << 8) {
        scratch[0] = (t << 5) | 24;
        scratch[1] = l as u8;
        buf.push(scratch[0]);
        buf.push(scratch[1]);
    } else if l < (1 << 16) {
        scratch[0] = (t << 5) | 25;
        let n = l as u16;
        scratch[2] = (n & 0xFF) as u8;
        scratch[1] = ((n >> 8) & 0xFF) as u8;
        for i in 0..3 {
            buf.push(scratch[i]);
        }
    } else if l < (1 << 32) {
        scratch[0] = (t << 5) | 26;
        let n = l as u32;
        scratch[4] = (n & 0xFF) as u8;
        scratch[3] = ((n >> 8) & 0xFF) as u8;
        scratch[2] = ((n >> 16) & 0xFF) as u8;
        scratch[1] = ((n >> 24) & 0xFF) as u8;
        for i in 0..5 {
            buf.push(scratch[i]);
        }
    } else {
        scratch[0] = (t << 5) | 27;
        let n = l as u64;
        scratch[8] = (n & 0xFF) as u8;
        scratch[7] = ((n >> 8) & 0xFF) as u8;
        scratch[6] = ((n >> 16) & 0xFF) as u8;
        scratch[5] = ((n >> 24) & 0xFF) as u8;
        scratch[4] = ((n >> 32) & 0xFF) as u8;
        scratch[3] = ((n >> 40) & 0xFF) as u8;
        scratch[2] = ((n >> 48) & 0xFF) as u8;
        scratch[1] = ((n >> 56) & 0xFF) as u8;
        for i in 0..9 {
            buf.push(scratch[i]);
        }
    }
}

/// 功  能: 序列化major type
///
/// 参  数:
///     t - 类型
///     l - 长度
///
/// 返回值: 无
///
fn cbor_encode_major_type(t: u8, l: u64) -> Vec<u8> {
    if l < 24 {
        let mut v = vec![0u8;1];
        v[0] = (t << 5) | (l as u8);
        v
    } else if l < (1 << 8) {
        let mut v = vec![0u8;2];
        v[0] = (t << 5) | 24;
        v[1] = l as u8;
        v
    } else if l < (1 << 16) {
        let mut v = vec![0u8;3];
        v[0] = (t << 5) | 25;
        let n = l as u16;
        v[2] = (n & 0xFF) as u8;
        v[1] = ((n >> 8) & 0xFF) as u8;
        v
    } else if l < (l << 32) {
        let mut v = vec![0u8;5];
        let n = l as u32;
        v[4] = (n & 0xFF) as u8;
        v[3] = ((n >> 8) & 0xFF) as u8;
        v[2] = ((n >> 16) & 0xFF) as u8;
        v[1] = ((n >> 24) & 0xFF) as u8;
        v
    } else {
        let mut v = vec![0u8;9];
        let n = l as u64;
        v[8] = (n & 0xFF) as u8;
        v[7] = ((n >> 8) & 0xFF) as u8;
        v[6] = ((n >> 16) & 0xFF) as u8;
        v[5] = ((n >> 24) & 0xFF) as u8;
        v[4] = ((n >> 32) & 0xFF) as u8;
        v[3] = ((n >> 40) & 0xFF) as u8;
        v[2] = ((n >> 48) & 0xFF) as u8;
        v[1] = ((n >> 56) & 0xFF) as u8;
        v
    }
}




