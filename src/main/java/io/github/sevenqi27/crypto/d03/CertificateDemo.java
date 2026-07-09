package io.github.sevenqi27.crypto.d03;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;

public class CertificateDemo {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * 总结：
     * 1.证书制作过程：密钥对 → builder → signer → holder → converter 转标准证书
     * 1a.密钥对，Demo1做的，不再赘述
     * 1b.builder，构造6个字段
     *      issuer:证书颁发者，可以使用根证书的直接传入，不用把数据取出来再构造，而是通过API保证了上级的主体是下级的签发者，这是证据：issuerCert.getSubjectX500Principal()
     *      SN:序列号，demo里用固定值；真实CA必须用大随机数——2008年有人利用可预测序列号+MD5碰撞伪造出真CA签的假证书
     *      notBefore:证书的生效日期
     *      notAfter:证书的截止日期
     *      subject:当前证书的信息
     *      publicKey:公钥，注意getPublicKey()取出的就是这里传进去的那把，证书不产生新钥匙
     *      六个参数里没有私钥——builder只攒待签内容，盖章是signer的事，内容和盖章是两个动作
     * 1c.signer，老生常谈的问题，注意算法、provider，这里要使用私钥；私钥传谁的就是谁在签发，整条链的层级关系只由这一个参数决定
     * 1d.holder，由builder构造出的X509结构对象
     * 1e.converter，把holder转成X509证书，注意要setProvider，如果不setProvider会报错
     * 2.证书验证
     * 2a.验证用的公钥是否为生成证书时的私钥对应的公钥，推导：如果是证书链，那么由于子证书用的是根证书的私钥，所以只能用根证书的公钥去验证，但是无法跨级验证——信任是一跳一跳传导的，不是传递闭包
     * 2b.时间的验证，checkValidity只做日期比较。notBefore/notAfter在签名保护范围内，篡改一个字节验签就崩（2a的实验就是证据），真正不可信的输入是验证方的时钟：checkValidity(Date)收谁的时间就信谁的。
     *    TSA证明的是"这个签名在时刻T已经存在"这一件事，从而把"签署时证书是否在有效期内"变成可证的
     * 2c.verify和checkValidity都是单张证书的检查；真实的链验证器(CertPathValidator/浏览器)会逐级验签+逐级查有效期，上级一过期整条链作废
     */
    public static void main(String[] args) throws Exception{
        KeyPair keyPair = getKeyPair();
        KeyPair subKeyPair = getKeyPair();
        X509Certificate rootCert = getRootCert(keyPair);

        System.out.println("根证书里的公钥==当初传进builder的公钥 → 期望 true, 实际 " + rootCert.getPublicKey().equals(keyPair.getPublic()));

        // ==================================== 子CA证书：用根的私钥签发 ====================================
        X500Name subject = new X500Name("CN=My Sub CA");
        // issuer直接传rootCert，API自动取根证书的subject当issuer，保证链条纪律
        JcaX509v3CertificateBuilder subBuilder = new JcaX509v3CertificateBuilder(rootCert, BigInteger.TEN, new Date(), new Date(System.currentTimeMillis() + 3600 * 1000L), subject, subKeyPair.getPublic());
        ContentSigner subContentSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder subHolder = subBuilder.build(subContentSigner);
        X509Certificate subCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(subHolder);

        subCert.verify(rootCert.getPublicKey());
        System.out.println("子证书用根公钥验证 → 期望通过, 实际通过 ✓");
        try {
            // 证书里装的是subKeyPair的公钥，但签名是根的私钥盖的——"证书里的公钥"和"验证这张证书用的公钥"是两把不同的钥匙
            subCert.verify(subKeyPair.getPublic());
            System.out.println("子证书用自己的公钥验证 → 期望 SignatureException, 实际通过了，才怪嘞 ✗");
        } catch (SignatureException e) {
            System.out.println("子证书用自己的公钥验证 → 期望 SignatureException, 实际 " + e.getClass().getSimpleName() + " ✓");
        }

        // ==================================== 闭环：字节写出去，CertificateFactory读回来 ====================================
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate parsedCert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(subCert.getEncoded()));
        parsedCert.verify(rootCert.getPublicKey());
        System.out.println("读回来的证书用根公钥验证 → 期望通过, 实际通过 ✓");
        System.out.println("读回来的字节==写出去的字节 → 期望 true, 实际 " + Arrays.equals(parsedCert.getEncoded(), subCert.getEncoded()));

        // ==================================== 用户证书：用子CA的私钥签发 ====================================
        KeyPair userKeyPair = getKeyPair();
        X500Name user = new X500Name("CN=User");
        // 故意给100小时，比上级SubCA的1小时还长——verify/checkValidity都是单张检查管不了这事；
        // 真实的链验证器逐级查有效期，上级过期整条链作废，这张证书实际寿命只有1小时（总结2c）
        JcaX509v3CertificateBuilder userBuilder = new JcaX509v3CertificateBuilder(subCert, BigInteger.TWO, new Date(), new Date(System.currentTimeMillis() + 100 * 3600 * 1000L), user, userKeyPair.getPublic());
        ContentSigner userSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(subKeyPair.getPrivate());
        X509Certificate userCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(userBuilder.build(userSigner));

        // 验证证书链：信任一跳一跳传导，不能跳级
        userCert.verify(subCert.getPublicKey());
        System.out.println("用户证书用子CA公钥验证 → 期望通过, 实际通过 ✓");
        try {
            userCert.verify(rootCert.getPublicKey());
            System.out.println("用户证书用根公钥验证(跳级) → 期望 SignatureException, 实际通过了，才怪嘞 ✗");
        } catch (SignatureException e) {
            System.out.println("用户证书用根公钥验证(跳级) → 期望 SignatureException, 实际 " + e.getClass().getSimpleName() + " ✓");
        }
    }


    static X509Certificate getRootCert(KeyPair keyPair) throws Exception {
        // 构造新的密钥对，用来验证不同公钥的
        KeyPair keyPair2 = getKeyPair();

        // 自签：issuer和subject是同一个身份，同一个对象用两次
        X500Name issuer = new X500Name("CN=My Root CA");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 3600 * 1000L), issuer, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);

        System.out.println("序列号: " + certificate.getSerialNumber());
        System.out.println("截止日期: " + certificate.getNotAfter());
        System.out.println("subject: " + certificate.getSubjectX500Principal() + ", issuer: " + certificate.getIssuerX500Principal() + " → 期望相同(自签)");

        certificate.verify(keyPair.getPublic());
        System.out.println("根证书用自己的公钥验证(自签) → 期望通过, 实际通过 ✓");
        certificate.checkValidity();
        System.out.println("有效期检查(现在) → 期望通过, 实际通过 ✓");

        try {
            // 传入其他公钥，预期抛出异常
            certificate.verify(keyPair2.getPublic());
            System.out.println("根证书用无关公钥验证 → 期望 SignatureException, 实际通过了，才怪嘞 ✗");
        } catch (SignatureException e) {
            System.out.println("根证书用无关公钥验证 → 期望 SignatureException, 实际 " + e.getClass().getSimpleName() + " ✓");
        }

        try {
            // 时钟是checkValidity的输入参数：把"现在"拨到10天后，模拟证书过期
            certificate.checkValidity(new Date(System.currentTimeMillis() + 10 * 24 * 3600 * 1000L));
            System.out.println("有效期检查(10天后) → 期望 CertificateExpiredException, 实际通过了，才怪嘞 ✗");
        } catch (CertificateExpiredException e) {
            System.out.println("有效期检查(10天后) → 期望 CertificateExpiredException, 实际 " + e.getClass().getSimpleName() + " ✓");
        }

        try {
            // 把"现在"拨到10天前，证书还没生效
            certificate.checkValidity(new Date(System.currentTimeMillis() - 10 * 24 * 3600 * 1000L));
            System.out.println("有效期检查(10天前) → 期望 CertificateNotYetValidException, 实际通过了，才怪嘞 ✗");
        } catch (CertificateNotYetValidException e) {
            System.out.println("有效期检查(10天前) → 期望 CertificateNotYetValidException, 实际 " + e.getClass().getSimpleName() + " ✓");
        }
        return certificate;
    }


    static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        return generator.generateKeyPair();
    }
}
