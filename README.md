# FIL钱包SDK  
FIL钱包sdk基于filecoin-ffi的rust版本，增加了一些新特性。

## 新特性
* 生成助记词/助记词恢复私钥。 
* 生成地址。
* 交易消息序列化。

## 说明
* 对于filecoin原有的功能（生成私钥、生成公钥、加密、签名、验签）并为作任何修改。  生成私钥的函数由新函数完成，该函数绑定了私钥种子和助记词。
* 地址支持SECP256K1和BLS算法的地址。  
* 交易序列化用的是filecoin最新V1版本的序列化算法。 

## 注意
* 所有的内存都是在sdk中分配的，需要调用sdk中对应的销毁函数，显式释放内存。
* 所有接口是以C风格导出的。
* 在Java中，可用JNI或JNA的方式调用，JNI稍显复杂，推荐使用JNA方式。

## 测试数据  
* 7b2254797065223a22626c73222c22507269766174654b6579223a2246714432463676383144655179754b4c595830717a2f476f65682b6462705a64744a304a34685558756a553d227d    
* 7b2254797065223a22626c73222c22507269766174654b6579223a22327353385374414c42776e544a313034556846667a45644443574f346c542b50397677697a6156726241413d227d    

## 连接节点
* /ip4/xxx/tcp/1347/p2p/12D3KooWDQ1dhTwPL2zyvK38QrCndjz9GQstSzWf5n9Rt1GKyPh1
* /ip4/xxx/tcp/1347/p2p/12D3KooWKQYdeAVKu3pUrqayeqCq1p9FwrYTriJRT7S2cykFrdsV
* /ip4/xxx/tcp/1347/p2p/12D3KooWGtkXNDgor18gSyf63ciQJA4ZjRxXgjcgyRY1N2W3RSNS


