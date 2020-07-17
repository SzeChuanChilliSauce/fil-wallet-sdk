extern crate lazy_static;
use blake2b_simd::{Params};
use std::collections::HashMap;
use std::io::BufRead;
use data_encoding::{BASE32, Specification, Encoding, BASE32_NOPAD};


///
pub const RAW:                  u64 = 0x55;
pub const DAG_PROTOBUF:         u64 = 0x70;
pub const DAG_CBOR:             u64 = 0x71;
pub const LIBP2P_KEY:           u64 = 0x72;
pub const GIT_RAW:              u64 = 0x78;
pub const ETH_BLOCK:            u64 = 0x90;
pub const ETH_BLOCK_LIST:       u64 = 0x91;
pub const ETH_TX_TRIE:          u64 = 0x92;
pub const ETH_TX:               u64 = 0x93;
pub const ETH_TX_RECEIPT_TRIE:  u64 = 0x94;
pub const ETH_TX_RECEIPT:       u64 = 0x95;
pub const ETH_STATE_TRIE:       u64 = 0x96;
pub const ETH_ACCOUNT_SNAPSHOT: u64 = 0x97;
pub const ETH_STORAGE_TRIE:     u64 = 0x98;
pub const BITCOIN_BLOCK:        u64 = 0xb0;
pub const BITCOIN_TX:           u64 = 0xb1;
pub const ZCASH_BLOCK:          u64 = 0xc0;
pub const ZCASH_TX:             u64 = 0xc1;
pub const DECRED_BLOCK:         u64 = 0xe0;
pub const DECRED_TX:            u64 = 0xe1;
pub const DASH_BLOCK:           u64 = 0xf0;
pub const DASH_TX:              u64 = 0xf1;

///
pub const IDENTITY:     u64 = 0x00;
pub const ID:           u64 = IDENTITY;
pub const SHA1:         u64 = 0x11;
pub const SHA2_256:     u64 = 0x12;
pub const SHA2_512:     u64 = 0x13;
pub const SHA3_224:     u64 = 0x17;
pub const SHA3_256:     u64 = 0x16;
pub const SHA3_384:     u64 = 0x15;
pub const SHA3_512:     u64 = 0x14;
pub const SHA3:         u64 = SHA3_512;
pub const KECCAK_224:   u64 = 0x1A;
pub const KECCAK_256:   u64 = 0x1B;
pub const KECCAK_384:   u64 = 0x1C;
pub const KECCAK_512:   u64 = 0x1D;
pub const SHAKE_128:    u64 = 0x18;
pub const SHAKE_256:    u64 = 0x19;
pub const BLAKE2B_MIN:  u64 = 0xb201;
pub const BLAKE2B_MAX:  u64 = 0xb240;
pub const BLAKE2S_MIN:  u64 = 0xb241;
pub const BLAKE2S_MAX:  u64 = 0xb260;
pub const MD5:          u64 = 0xd5;
pub const DBL_SHA2_256: u64 = 0x56;
pub const MURMUR3_128:  u64 = 0x22;
pub const MURMUR3:      u64 = MURMUR3_128;
pub const X11:          u64 = 0x1100;
pub const BLAKE2B_256:  u64 = 0xb220;

///
const LEN8TAB: [u8;256] = [
    0x00, 0x01, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
];

/// base32编码表
const BAS32_ALPHABET:[u8;32] = [97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
                                107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
                                117, 118, 119, 120, 121, 122, 50, 51, 52, 53, 54, 55];

/// 各种算法和数字的映射关系
lazy_static::lazy_static! {
    pub static ref NAMES: HashMap<&'static str, u64> = {
        let mut map = HashMap::new();
        map.insert("identity", IDENTITY);
        map.insert("sha1", SHA1);
        map.insert("sha2-256", SHA2_256);
        map.insert("sha2-512", SHA2_512);
        map.insert("sha3", SHA3_512);
        map.insert("sha3-224", SHA3_224);
        map.insert("sha3-256", SHA3_256);
        map.insert("sha3-384", SHA3_384);
        map.insert("sha3-512", SHA3_512);
        map.insert("dbl-sha2-256", DBL_SHA2_256);
        map.insert("murmur3-128", MURMUR3_128);
        map.insert("keccak-224", KECCAK_224);
        map.insert("keccak-256", KECCAK_256);
        map.insert("keccak-384", KECCAK_384);
        map.insert("keccak-512", KECCAK_512);
        map.insert("shake-128", SHAKE_128);
        map.insert("shake-256", SHAKE_256);
        map.insert("x11", X11);
        map.insert("md5", MD5);
        map.insert("blake2b-256", BLAKE2B_256);
        map
    };

    pub static ref CODES: HashMap<u64, &'static str> = {
        let mut map = HashMap::new();
        map.insert(IDENTITY, "identity");
        map.insert(SHA1, "sha1");
        map.insert(SHA2_256, "sha2-256");
        map.insert(SHA2_512, "sha2-512");
        map.insert(SHA3_224, "sha3-224");
        map.insert(SHA3_256, "sha3-256");
        map.insert(SHA3_384, "sha3-384");
        map.insert(SHA3_512, "sha3-512");
        map.insert(DBL_SHA2_256, "dbl-sha2-256");
        map.insert(MURMUR3_128, "murmur3-128");
        map.insert(KECCAK_224, "keccak-224");
        map.insert(KECCAK_256, "keccak-256");
        map.insert(KECCAK_384, "keccak-384");
        map.insert(KECCAK_512, "keccak-512");
        map.insert(SHAKE_128, "shake-128");
        map.insert(SHAKE_256, "shake-256");
        map.insert(X11, "x11");
        map.insert(MD5, "md5");
        map.insert(BLAKE2B_256, "blake2b-256");
        map
    };

    pub static ref DEFAULT_LENGTH: HashMap<u64, i32> = {
        let mut map = HashMap::new();
        map.insert(IDENTITY, -1);
        map.insert(SHA1, 20);
        map.insert(SHA2_256, 32);
        map.insert(SHA2_512, 64);
        map.insert(SHA3_224, 28);
        map.insert(SHA3_256, 32);
        map.insert(SHA3_384, 48);
        map.insert(SHA3_512, 64);
        map.insert(DBL_SHA2_256, 32);
        map.insert(KECCAK_224, 28);
        map.insert(KECCAK_256, 32);
        map.insert(MURMUR3_128, 4);
        map.insert(KECCAK_384, 48);
        map.insert(KECCAK_512, 64);
        map.insert(SHAKE_128, 32);
        map.insert(SHAKE_256, 64);
        map.insert(X11, 64);
        map.insert(MD5, 16);
        map.insert(BLAKE2B_256, 32);
        map
    };
}


///
#[derive(Debug)]
pub struct V1Builder {
    pub codec: u64,
    pub mh_type: u64,
    pub mh_length: i32, // 如果mh_length<=0，就取默认长度
}

/// V1Builder
/// version 1版本的序列化
impl V1Builder {
    pub fn sum(&self, data: &mut Vec<u8>) -> Vec<u8> {
        let mut mh_len = self.mh_length;
        if mh_len <= 0 {
            mh_len = -1;
        }

        // 计算data的multi hash
        let mut mhash = multi_hash_sum(data, &self.mh_type,mh_len);

        // 构造V1 cid
        let l = mhash.len();
        let c = uvarint_size(self.codec);
        let mut cid_bytes: Vec<u8> = vec![0u8;1+c+l];

        // 由于是V1版本，1是版本号
        let mut  n = put_uvarint(cid_bytes.as_mut(), 1, 0);
        let m = put_uvarint(cid_bytes.as_mut(), self.codec, n);
        n += m;
        for i in 0..l {
            cid_bytes[i+n] = mhash[i];
        }

        cid_bytes
    }
}

/// 功  能: 计算multi hash
///
/// 参  数:
///     data   - 输入数据
///     typ    - v1的算法类型
///     length - v1的输出长度
///
/// 返回值: multi hash
///
fn multi_hash_sum(data: &mut Vec<u8>, typ: &u64, mut length: i32) -> Vec<u8> {
    if length < 0 {
        length = DEFAULT_LENGTH[typ];
    }

    // 计算摘要
    // 摘要算法：blake2b
    // 输出长度：32字节
    let mhash = Params::new()
        .hash_length(length as usize)
        .to_state()
        .update(data.as_slice())
        .finalize();

    // new cid v1
    let l = mhash.as_bytes().len();
    let mut buf: Vec<u8> = vec![0u8; uvarint_size(*typ)+ uvarint_size(l as u64) + l];
    let mut n = put_uvarint(buf.as_mut(), *typ, 0);
    let m= put_uvarint(buf.as_mut(), l as u64, n);
    n += m;
    let bytes = mhash.as_bytes();
    for i in 0..l {
        buf[n as usize + i] = bytes[i];
    }

    buf
}

/// 功  能: 向buf中按字节写入x
///
/// 参  数:
///     buf    - 缓冲区
///     x      - 整数
///     offset - 向对于buff开始的偏移量
///
/// 返回值: 返回
///
fn put_uvarint(buf: &mut Vec<u8>, mut x: u64, offset: usize) -> usize {
    let mut i = 0;

    while x >= 0x80 {
        buf[i+offset] = (x as u8) | 0x80;
        x >>= 7;
        i += 1;
    }
    buf[i+offset] = x as u8;

    i + 1
}

/// 功  能: 计算整数的位数
///
/// 参  数:
///     num - 64位无符号整数
///
/// 返回值: 整数位数
///
fn uvarint_size(num: u64) -> usize {
    let bits = len64(num);
    let q = bits / 7;
    let r = bits % 7;

    let mut size = q;
    if r > 0 || size == 0 {
        size += 1;
    }

    size
}

/// 功  能: 返回整数x需要的最小位数
///
/// 参  数:
///     x - 64位无符号正数
///
/// 返回值: 需要的最小位数
///
fn len64(mut x: u64) -> usize {
    let mut n = 0;

    if x >= (1 << 32) {
        x >>= 32;
        n = 32;
    }
    if x >= (1 << 16) {
        x >>= 16;
        n += 16;
    }
    if x >= (1 << 8) {
        x >>= 8;
        n += 8;
    }

    (n + LEN8TAB[x as usize]) as usize
}

/// 功  能: 获取字符在base32编码表中的位置
///
/// 参  数:
///     c - base32字符
///
/// 返回值: 字符在编码表中的位置
///
fn get_char_index(c: u8) -> i32 {
    let index = 0;
    for i in 0..BAS32_ALPHABET.len() {
        if c == BAS32_ALPHABET[i] {
            return i as u8 as i32;
        }
    }

    index
}

/// 功  能: base32解码
///
/// 参  数:
///     input - base32字符串
///
/// 返回值: 解码后字节数组
///
pub fn fil_base32_decode(input: &str) -> Vec<u8> {
    let input_len = input.len();
    // 解码后地址的长度
    let out_len = ((input_len as f32 + 1.6 - 1.0) / 1.6) as usize;

    let bytes = input.as_bytes();
    let mut decoded: Vec<u8> = vec![0u8;out_len];

    let mut mask: u8 = 0;
    let mut current_byte: u8 = 0;
    let mut bits_left: usize = 8;

    let mut i: usize = 0;
    let mut j: usize = 0;
    while i < input_len {
        let index = get_char_index(bytes[i]);
        if bits_left > 5 {
            mask = (index << ((bits_left - 5) as u8) as i32) as u8;
            current_byte |= mask;
            bits_left -= 5;
        } else {
            mask = (index >> ((5 - bits_left) as u8) as i32) as u8;
            current_byte |= mask;
            decoded[j] = current_byte;
            current_byte = (index << ((8 - 5 + bits_left) as u8) as i32) as u8;
            bits_left += 8 - 5;
            j+=1;
        }
        i += 1
    }

    decoded
}

/// 功  能: base32编码
///
/// 参  数:
///     data - 需编码的字节数组
///
/// 返回值: 编码后的字节数组
///
pub fn fil_base32_encode(data: &[u8]) -> Vec<u8> {
    let encoded = BASE32_NOPAD.encode(data.as_ref());
    let data = encoded.into_bytes();

    let mut res: Vec<u8> = Vec::new();
    let l = data.len();

    for i in  0..l {
        if data[i] >= 48 && data[i] <= 57 {
            res.push(data[i]);
        }else{
            res.push(data[i]+32);
        }
    }

    res

    /*
    let length = data.len();
    let mut extra = 0;
    // 求余
    match length%5 {
        4 => {
            extra = (4*8)/5+1;
        }
        3 => {
            extra = (3*8)/5+1;
        }
        2 => {
            extra = (2*8)/5+1;
        }
        1 => {
            extra = 8/5+1;
        }
        _ => {}
    };

    // 计算输出的长度
    let out_len = length/5*8+extra;
    let mut encoded_data:Vec<u8> = vec![0; out_len];

    let mut first_byte: u64 = 0;
    let mut second_byte: u64 = 0;
    let mut third_byte: u64 = 0;
    let mut fourth_byte: u64 = 0;
    let mut fifth_byte: u64 = 0;

    let mut i: usize = 0;
    let mut j: usize = 0;

    while i+5 < length {
        let mut num:u64 = 0;

        if i < length {
            first_byte = data[i] as u64;
        } else {
            first_byte = 0 ;
        }

        if i < length {
            second_byte = data[i+1] as u64;
        } else {
            second_byte = 0;
        }

        if i < length {
            third_byte = data[i+2] as u64;
        } else {
            third_byte = 0;
        }

        if i < length {
            fourth_byte = data[i+3] as u64;
        } else {
            fourth_byte = 0;
        }

        if i < length {
            fifth_byte = data[i+4] as u64;
        } else {
            fifth_byte = 0;
        }

        num = ((first_byte >> 3) << 35) +
            ((((first_byte  & 0x07) << 2) | (second_byte >> 6)) << 30 ) +
            (((second_byte  & 0x3f) >> 1) << 25) +
            ((((second_byte & 0x01) << 4) | (third_byte  >> 4)) << 20) +
            ((((third_byte  & 0x0f) << 1) | (fourth_byte >> 7)) << 15) +
            (((fourth_byte  & 0x7f) >> 2) << 10) +
            ((((fourth_byte & 0x3)  << 3) | (fifth_byte  >> 5)) << 5) +
            (fifth_byte     & 0x1f);


        encoded_data[j] = BAS32_ALPHABET[((num >> 35) & 0x1f) as usize];
        j+=1;
        encoded_data[j] = BAS32_ALPHABET[((num >> 30) & 0x1f) as usize];
        j+=1;
        encoded_data[j] = BAS32_ALPHABET[((num >> 25) & 0x1f) as usize];
        j+=1;
        encoded_data[j] = BAS32_ALPHABET[((num >> 20) & 0x1f) as usize];
        j+=1;
        encoded_data[j] = BAS32_ALPHABET[((num >> 15) & 0x1f) as usize];
        j+=1;
        encoded_data[j] = BAS32_ALPHABET[((num >> 10) & 0x1f) as usize];
        j+=1;
        encoded_data[j] = BAS32_ALPHABET[((num >> 5)  & 0x1f) as usize];
        j+=1;
        encoded_data[j] = BAS32_ALPHABET[(num & 0x1f) as usize];
        j+=1;

        i += 5;
    }


    first_byte = 0;
    second_byte = 0;
    third_byte = 0;
    fourth_byte = 0;
    fifth_byte = 0;

    let mut num: u64 = 0;
    match length%5 {
        4 => {
            first_byte  = data[length-4] as u64;
            second_byte = data[length-3] as u64;
            third_byte  = data[length-2] as u64;
            fourth_byte = data[length-1] as u64;

            num = ((first_byte >> 3) << 30) +
                ((((first_byte  & 0x07) << 2) | (second_byte >> 6)) << 25) +
                (((second_byte  & 0x3f) >> 1) << 20) +
                ((((second_byte & 0x01) << 4) | (third_byte >> 4)) << 15) +
                ((((third_byte  & 0x0f) << 1) | (fourth_byte >> 7)) << 10) +
                (((fourth_byte  & 0x7f) >> 2) << 5) +
                ((fourth_byte   & 0x03) << 3);

            encoded_data[j] = BAS32_ALPHABET[((num >> 30) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 25) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 20) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 15) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 10) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 5)  & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[(num & 0x1f) as usize];
        }

        3 => {
            first_byte  = data[length-3] as u64;
            second_byte = data[length-2] as u64;
            third_byte  = data[length-1] as u64;


            num = ((first_byte >> 3) << 20) +
                ((((first_byte  & 0x07) << 2) | (second_byte >> 6)) << 15) +
                (((second_byte  & 0x3f) >> 1) << 10) +
                ((((second_byte & 0x01) << 4) | (third_byte >> 4)) << 5) +
                ((third_byte    & 0x0f) << 1);

            encoded_data[j] = BAS32_ALPHABET[((num >> 20) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 15) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 10) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 5)  & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[(num & 0x1f) as usize];
        }

        2 => {
            first_byte  = data[length-2] as u64;
            second_byte = data[length-1] as u64;

            num = ((first_byte >> 3) << 15) +
                ((((first_byte & 0x07) << 2) | (second_byte >> 6)) << 10) +
                (((second_byte & 0x3f) >> 1) << 5) +
                (second_byte   & 0x01);

            encoded_data[j] = BAS32_ALPHABET[((num >> 15) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 10) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[((num >> 5)  & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[(num & 0x1f) as usize];
        }

        1 => {
            first_byte = data[length-1] as u64;

            num = ((first_byte >> 3) << 5) +  ((first_byte & 0x07) << 2);

            encoded_data[j] = BAS32_ALPHABET[((num >> 5) & 0x1f) as usize];
            j += 1;
            encoded_data[j] = BAS32_ALPHABET[(num & 0x1f) as usize];
        }

        _ => {}
    }

    encoded_data
     */
}