# Filcoin钱包SDK  
Filcoin钱包sdk基于filecoin-ffi的rust版本，增加了一些新特性。

## 新特性
* 生成助记词/助记词恢复私钥  
* 生成地址  
* 交易消息序列化  

## 说明
* 对于filecoin原有的功能（生成私钥、私钥生成公钥、加密、签名、验签）并为作任何修改。生成私钥的函数由新函数完成，该函数绑定了私钥种子和助记词。
* 地址目前只支持BLS格式的地址。  
* 交易序列化用的是filecoin最新V1版本的序列化算法。 

