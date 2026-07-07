package io.github.sevenqi27.crypto.d02;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class DigestDemo {

    private static final String ALG_NONE_WITH_ECDSA = "NONEwithECDSA";
    private static final String ALG_SHA256_WITH_ECDSA = "SHA256withECDSA";
    private static final String PROVIDER_BC = "BC";


    static {
        // 得手动显式把BC的Provider注册到java security中，放在静态代码块中保证只被加载了一次
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 总结：
     * 1.不要乱用算法，在自己不了解清楚的前提下，把SHA256withECDSA的不带计算摘要理解为ECDSA，并且没有去查询资料确认，也没有做交叉验证，导致虽然验签通过，但是用了一个已经被判死刑的摘要算法
     * 2.以后不能说私钥加密公钥解密这种说法，在ECDSA的签名算法领域是一个随机数k+私钥算出一个点
     * 3.验签结果成功与否，取决于密钥、加签算法以及数据
     * 4.ECDSA是签名算法，属于非对称密码体系
     * 5.非对称密码在代码体现的是，加签的时候，初始化加签的配置用的是私钥，验签的时候，初始化验签的配置用的是公钥
     */
    public static void main(String[] args) throws Exception {
        String message = "test message";
        String message1 = "test messag";
        MessageDigest instance = MessageDigest.getInstance("SHA-256");

        byte[] digest = instance.digest(message.getBytes(StandardCharsets.UTF_8));
        byte[] digest1 = instance.digest(message1.getBytes(StandardCharsets.UTF_8));
        KeyPair keyPair = getKeyPair();
        KeyPair keyPairNew = getKeyPair();

        byte[] signature = sign(digest, keyPair.getPrivate(), ALG_NONE_WITH_ECDSA, PROVIDER_BC);
        byte[] signatureNew = sign(digest, keyPairNew.getPrivate(), ALG_NONE_WITH_ECDSA, PROVIDER_BC);
        byte[] signatureWithMessage = sign(message.getBytes(StandardCharsets.UTF_8), keyPair.getPrivate(), ALG_SHA256_WITH_ECDSA, PROVIDER_BC);

        // 验证
        System.out.println("正常摘要验签       → 期望 true,  实际 " + verify(digest, signature, keyPair.getPublic(), ALG_NONE_WITH_ECDSA, PROVIDER_BC));
        System.out.println("正常原文验签       → 期望 true,  实际 " + verify(message.getBytes(StandardCharsets.UTF_8), signatureWithMessage, keyPair.getPublic(), ALG_SHA256_WITH_ECDSA, PROVIDER_BC));
        System.out.println("篡改摘要       → 期望 false, 实际 " + verify(digest1, signature, keyPair.getPublic(), ALG_NONE_WITH_ECDSA, PROVIDER_BC));
        System.out.println("换公钥         → 期望 false, 实际 " + verify(digest,  signature,    keyPairNew.getPublic(), ALG_NONE_WITH_ECDSA, PROVIDER_BC));
        System.out.println("别人私钥签的   → 期望 false, 实际 " + verify(digest,  signatureNew, keyPair.getPublic(), ALG_NONE_WITH_ECDSA, PROVIDER_BC));


        System.out.println("摘要签的名用原文验(跨算法) → 期望 true,  实际 " + verify(message.getBytes(StandardCharsets.UTF_8), signature, keyPair.getPublic(), ALG_SHA256_WITH_ECDSA, PROVIDER_BC));
        System.out.println("原文签的名用摘要验(跨算法) → 期望 true,  实际 " + verify(digest, signatureWithMessage, keyPair.getPublic(), ALG_NONE_WITH_ECDSA, PROVIDER_BC));

        // 同私钥同数据签两次，结果不同：ECDSA 每次签名掷一个一次性随机数 k（总结第 2 条的实证；k 重用 = PS3 私钥泄露事故）
        byte[] signAgain = sign(digest, keyPair.getPrivate(), ALG_NONE_WITH_ECDSA, PROVIDER_BC);
        System.out.println("同私钥同数据两次签名相同吗 → 期望 false, 实际 " + java.util.Arrays.equals(signature, signAgain));
    }

    /**
     * 摘要加签
     * @param digest 摘要数据
     * @param privateKey 私钥
     * @param alg 签名算法
     * @param provider 签名提供方
     * @return 加签数据
     * @throws Exception 异常处理
     */
    static byte[] sign(byte[] digest, PrivateKey privateKey, String alg, String provider) throws Exception {
        // 加签
        Signature signature = getSignatureInstance(alg, provider);
        signature.initSign(privateKey);
        signature.update(digest);
        byte[] sign = signature.sign();
        System.out.println(Hex.toHexString(sign));
        return sign;
    }


    /**
     * 验签
     *
     */
    static boolean verify(byte[] digest, byte[] signature, PublicKey publicKey, String alg, String provider) throws Exception {
        // 验签
        Signature verifySignature = getSignatureInstance(alg, provider);
        verifySignature.initVerify(publicKey);
        verifySignature.update(digest);
        return verifySignature.verify(signature);
    }

    static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        return generator.generateKeyPair();
    }


    static Signature getSignatureInstance(String alg, String provider) throws Exception {
        return Signature.getInstance(alg, provider);
    }

}
