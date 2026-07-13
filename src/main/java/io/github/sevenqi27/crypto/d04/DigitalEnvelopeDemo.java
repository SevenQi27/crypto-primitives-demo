package io.github.sevenqi27.crypto.d04;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class DigitalEnvelopeDemo {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * 总结：
     * 1.信封结构：会话AES密钥加密数据(GCM) + 接收方公钥加密会话密钥(ECIES)，
     *   四件东西要一起上路：加密后的密钥、GCM IV、ECIES nonce、密文——见DEnvelope。
     *   JCA故意不提供信封类：JCA的边界是密码原语，信封是报文格式，归标准管(CMS EnvelopedData/JWE)
     * 2.RSA有~245字节上限，因为明文亲自参与数学运算(2048位模数，PKCS#1 padding吃掉11字节：随机数+分隔符+头部)；
     *   EC的数学里根本没有"加密"这种运算，原生只会两件事：签名(ECDSA，demo02)和密钥协商(ECDH)
     * 3.ECDH隔空同数：Alice私钥×Bob公钥 = Bob私钥×Alice公钥 = ab×G，双方各自在家算出同一个秘密，
     *   窃听者只有两把公钥拼不出来。裸秘密要过KDF再当密钥用。
     *   静态密钥对协商结果永远相同→生产用临时密钥对(ECDHE)每次注入256位新鲜随机数，顺带买到前向保密(TLS即此)
     * 4.ECIES=临时密钥对+ECDH+KDF+AES-CBC的出厂密封信封，真正碰数据的自始至终是AES，所以无长度限制；
     *   密文头部第一个字节0x04就是那把明文的临时公钥(未压缩EC点标记)。
     *   本demo用ECIES包AES密钥=信封套信封，即JWE的ECDH-ES+A256KW结构
     * 5.AAD：GCM把AAD、密文、长度全部搅进同一个GHASH算出一个tag，所以改AAD/翻密文/换密钥/截tag
     *   抛的是同一个AEADBadTagException——错误统一不泄密是故意的(CBC padding oracle前车之鉴)。
     *   消息文本是provider方言(BC:"mac check in GCM failed" / SunJCE:"Tag mismatch")，异常类才是API合同。
     *   报错不作证，探针的控制变量才是证据
     * 6.公理：确定性就是泄漏——每次密码学操作都要一次新鲜随机性，各家进门不同：
     *   RSA padding随机字节 / GCM每次新IV / ECDSA每次新k(demo02) / ECDH临时密钥对 / 证书随机SN(demo03)。
     *   零随机性的反面证物是ECB：见EcbPatternProbe(重复块hex)和EcbPenguinPicture(企鹅图实物)
     */
    public static void main(String[] args) throws Exception{
        // 整体过程：生成AES密钥，加密数据，加密密钥，构造信封，存入加密后的和加密数据，私钥解密密钥，用密钥解密数据
        // 结果验证：验证密钥，验证加密数据，验证加密后的密钥

        // 数据准备：待加密的数据
        String message = "hello world";
        // 数据准备：其余业务数据，比如主键id
        String id = "id:100001";
        String type = "type:test";
        String id1 = "id:100002";

        // 数据准备：发送方加密用的密钥
        SecretKey secretKey = generateSenderSecretKey();
        System.out.println("发送方密钥(Base64)：" + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        // 数据准备：接收方的EC密钥对
        KeyPair keyPair = generateReceiverKeyPair();



        // 加密数据
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        byte[] dataIV = generateIV();
        GCMParameterSpec iv = new GCMParameterSpec(128, dataIV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        // 还能附加一些业务数据
        cipher.updateAAD(id.getBytes(StandardCharsets.UTF_8));
        cipher.updateAAD(type.getBytes(StandardCharsets.UTF_8));
        byte[] encryptData = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // 加密密钥
        // ECIESwithAES-CBC内部也使用AES-CBC，因此需要单独的16字节IV；它和上面正文加密使用的GCM IV不是同一个东西
        byte[] eciesIV = generateECIESIV();
        IESParameterSpec iesParameterSpec = new IESParameterSpec(null, null, 128, 256, eciesIV);
        Cipher receiverPublicKeyCipher = Cipher.getInstance("ECIESwithAES-CBC", "BC");
        receiverPublicKeyCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), iesParameterSpec, new SecureRandom());
        byte[] encryptedSecretKey = receiverPublicKeyCipher.doFinal(secretKey.getEncoded());


        // 发送方加密后的数据
        System.out.println("加密后的数据(转Base64)：" + Base64.getEncoder().encodeToString(encryptData));
        System.out.println("加密后的密钥(转Base64)：" + Base64.getEncoder().encodeToString(encryptedSecretKey));

        DEnvelope envelope = new DEnvelope();
        envelope.setEciesIv(eciesIV);
        envelope.setEncryptData(encryptData);
        envelope.setEncryptSecretKey(encryptedSecretKey);
        envelope.setIv(dataIV);
        envelope.setId(id);
        envelope.setType(type);

        // 接收方接收到数据后开始解密
        // 解密密钥
        Cipher receiverCipher = Cipher.getInstance("ECIESwithAES-CBC", "BC");
        IESParameterSpec iesParameterSpec1 = new IESParameterSpec(null, null, 128, 256, envelope.getEciesIv());
        receiverCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), iesParameterSpec1);
        byte[] decryptSecretKey = receiverCipher.doFinal(envelope.getEncryptSecretKey());
        SecretKeySpec aes = new SecretKeySpec(decryptSecretKey, "AES");
        System.out.println("解密后的发送方密钥(Base64)：" + Base64.getEncoder().encodeToString(decryptSecretKey));
        System.out.println("发送方密钥与解密后的密钥是否一致：" + Arrays.equals(secretKey.getEncoded(), decryptSecretKey));

        Cipher decryptData = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        decryptData.init(Cipher.DECRYPT_MODE, aes, new GCMParameterSpec(128, envelope.getIv()));
        decryptData.updateAAD(envelope.getId().getBytes(StandardCharsets.UTF_8));
        decryptData.updateAAD(envelope.getType().getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = decryptData.doFinal(envelope.getEncryptData());
        System.out.println("解密后的数据：" + new String(decrypted, StandardCharsets.UTF_8));
        System.out.println("原数据与解密后的数据是否一致：" + Arrays.equals(message.getBytes(StandardCharsets.UTF_8), decrypted));


        Cipher decryptDataFailed = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        decryptDataFailed.init(Cipher.DECRYPT_MODE, aes, iv);
        decryptDataFailed.updateAAD(envelope.getId().getBytes(StandardCharsets.UTF_8));
        try {
            byte[] decryptedFailed = decryptDataFailed.doFinal(encryptData);
            System.out.println("解密后的数据：" + new String(decryptedFailed, StandardCharsets.UTF_8));
            System.out.println("原数据与解密后的数据是否一致：" + Arrays.equals(message.getBytes(StandardCharsets.UTF_8), decryptedFailed));
        } catch (AEADBadTagException e) {
            System.out.println("解密失败,原因是有两个add，而这里只传了一个,抛出了异常类" + e.getClass().getName());
        }


        Cipher decryptDataFailed1 = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        decryptDataFailed1.init(Cipher.DECRYPT_MODE, aes, iv);
        // 篡改信封数据
        envelope.setId(id1);
        decryptDataFailed1.updateAAD(envelope.getId().getBytes(StandardCharsets.UTF_8));
        decryptDataFailed1.updateAAD(envelope.getType().getBytes(StandardCharsets.UTF_8));
        try {
            byte[] decryptedFailed1 = decryptDataFailed1.doFinal(encryptData);
            System.out.println("解密后的数据：" + new String(decryptedFailed1, StandardCharsets.UTF_8));
            System.out.println("原数据与解密后的数据是否一致：" + Arrays.equals(message.getBytes(StandardCharsets.UTF_8), decryptedFailed1));
        } catch (AEADBadTagException e) {
            System.out.println("解密失败,原因是有人篡改了aad的数据,抛出了异常类" + e.getClass().getName());
        }


        KeyPairGenerator aliceKey = KeyPairGenerator.getInstance("EC", "BC");
        aliceKey.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        KeyPair aliceKeyPair = aliceKey.generateKeyPair();

        KeyPairGenerator bobKey = KeyPairGenerator.getInstance("EC", "BC");
        bobKey.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        KeyPair bobKeyPair = bobKey.generateKeyPair();


        KeyAgreement sender = KeyAgreement.getInstance("ECDH", "BC");
        sender.init(aliceKeyPair.getPrivate());
        sender.doPhase(bobKeyPair.getPublic(), true);
        byte[] senderSecret = sender.generateSecret();
        System.out.println("Alice私钥+bob公钥协商后生成的密钥：" + Base64.getEncoder().encodeToString(senderSecret));

        KeyAgreement receiver = KeyAgreement.getInstance("ECDH", "BC");
        receiver.init(bobKeyPair.getPrivate());
        receiver.doPhase(aliceKeyPair.getPublic(), true);
        byte[] receiverSecret = receiver.generateSecret();
        System.out.println("Bob私钥+Alice公钥协商后生成的密钥：" + Base64.getEncoder().encodeToString(receiverSecret));

        System.out.println("是否一致(期望true):" + Arrays.equals(senderSecret, receiverSecret));

        // 验证,接收方用了非发送方的公钥
        KeyAgreement receiver1 = KeyAgreement.getInstance("ECDH", "BC");
        receiver1.init(bobKeyPair.getPrivate());
        receiver1.doPhase(keyPair.getPublic(), true);
        byte[] notAlicePublicKeyGenerateSecret = receiver1.generateSecret();

        // 期望是false
        System.out.println("是否一致(期望false)" + Arrays.equals(senderSecret, notAlicePublicKeyGenerateSecret));


    }


    public static SecretKey generateSenderSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }


    public static KeyPair generateReceiverKeyPair() throws Exception{
        KeyPairGenerator instance = KeyPairGenerator.getInstance("EC", "BC");
        instance.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        return instance.generateKeyPair();
    }

    /**
     * 生成12字节的IV
     * @return
     */
    public static byte[] generateIV(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[12];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * 生成ECIES内部AES-CBC使用的16字节IV
     * @return
     */
    public static byte[] generateECIESIV(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return bytes;
    }



}

class DEnvelope {
    /**
     * 加密后的数据
     */
    private byte[] encryptData;

    /**
     * 加密后的key
     */
    private byte[] encryptSecretKey;

    /**
     * IV
     */
    private byte[] iv;

    /**
     * eciesIV
     */
    private byte[] eciesIv;

    /**
     * 业务id
     */
    private String id;

    /**
     * 业务类型
     */
    private String type;

    public byte[] getEncryptData() {
        return encryptData;
    }

    public void setEncryptData(byte[] encryptData) {
        this.encryptData = encryptData;
    }

    public byte[] getEncryptSecretKey() {
        return encryptSecretKey;
    }

    public void setEncryptSecretKey(byte[] encryptSecretKey) {
        this.encryptSecretKey = encryptSecretKey;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getEciesIv() {
        return eciesIv;
    }

    public void setEciesIv(byte[] eciesIv) {
        this.eciesIv = eciesIv;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
