package io.github.sevenqi27.crypto.d05;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * 总结：
 * 1.钱包地址不是新密码学，就是"公钥 → 哈希 → 编码"三步，BTC/ETH 只是各选了不同的哈希和编码
 * 2.ETH线：X‖Y 64字节(去0x04头，坐标BigInteger必须左补零对齐32字节) → KECCAK-256 → 取后20字节 → 0x+hex。
 *   注意 Keccak-256 ≠ SHA3-256：以太坊用NIST标准化之前的原版，padding字节不同，用错了地址照样算得出来但永远收不到钱
 * 3.BTC线(P2PKH)：公钥字节(压缩33/未压缩65) → SHA-256 → RIPEMD-160 → [0x00版本][hash160×20][双SHA-256前4字节校验和]
 *   共25字节 → 手写Base58。同一把私钥的压缩/未压缩公钥出两个都合法且互不相通的地址——老钱包跨软件导入余额对不上的根源
 * 4.Base58就是大数除58取余查表(字母表58字符，无0OIl防抄错)，两个暗坑本demo都真实踩过：
 *   4a.终止条件是"商为零(数除完)"不是"余数为零"——余数0是合法字符'1'必须append，写错约四成真实地址被截断
 *   4b.前导0x00每个单独转一个'1'，且必须数"输入的原始字节"——BigInteger看不见前导零(25字节bitLength=192不是200为证)，
 *      输出的Base58字符里也永远没有0x00。硬编码"1"会在hash160自身以0x00开头时(概率1/256)少补一位，托管系统里这叫资损事故
 * 5.独立裁判升级：私钥=1的地址是全网公认测试向量，代码从数学推、向量从链上共识来，两个独立来源撞出同一答案才算过
 * 6.但本demo最贵的一课：4a/4b两个bug存在时公认向量照样全过(两个向量恰好不含字符'1'且恰好只有一个前导零)——
 *   通过的测试只认证它走过的路径。所以补了两个对抗探针：base58(58)必须="21"、双前导零输入必须以"11"开头。
 *   与demo04"报错不作证，控制变量才是证据"同族：证据的效力边界，永远比你以为的窄
 */
public class BtcAddressDemo {

    private static final String STRING = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static void main(String[] args) throws Exception{

        // ETH的我先手动实现下，以下是ETH的
        BigInteger privateKeyETH = BigInteger.ONE;
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint publicKeyETH = curve.getG().multiply(privateKeyETH).normalize();

        byte[] xETH = to32Bytes(publicKeyETH.getAffineXCoord().toBigInteger());
        byte[] yETH = to32Bytes(publicKeyETH.getAffineYCoord().toBigInteger());

        byte[] xyETH = new byte[64];
        System.arraycopy(xETH, 0, xyETH, 0, 32);
        System.arraycopy(yETH, 0, xyETH, 32, 32);


        byte[] hash = MessageDigest.getInstance("KECCAK-256", "BC").digest(xyETH);
        byte[] addressBytesETH = Arrays.copyOfRange(hash, 12, 32);

        String addressETH = "0x" + HexFormat.of().formatHex(addressBytesETH);

        String wellKnowETH = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

        System.out.println("== ETH：私钥=1 对表 ==");
        System.out.println("推导结果：" + addressETH);
        System.out.println("与公认向量是否一致(期望true)：" + addressETH.equals(wellKnowETH));


        // 接下来就是BTC的了：私钥=1，压缩/未压缩一次跑齐
        BigInteger privateKeyBTC = BigInteger.ONE;
        ECPoint publicKeyBTC = curve.getG().multiply(privateKeyBTC).normalize();

        String uncompressed = btcAddress(publicKeyBTC, false);
        String compressed = btcAddress(publicKeyBTC, true);
        String wellKnowUncompressed = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm";
        String wellKnowCompressed = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

        System.out.println("\n== BTC：私钥=1 对表 ==");
        System.out.println("未压缩推导：" + uncompressed);
        System.out.println("与公认向量一致(期望true)：" + uncompressed.equals(wellKnowUncompressed));
        System.out.println("压缩推导：" + compressed);
        System.out.println("与公认向量一致(期望true)：" + compressed.equals(wellKnowCompressed));
        System.out.println("同一私钥两地址互不相同(期望true)：" + !uncompressed.equals(compressed));


        // 对抗探针：公认向量过了不代表代码对——两个向量恰好不含'1'也恰好只有一个前导零，
        // 下面两针专打曾经真实写出来过的两个bug
        System.out.println("\n== Base58 对抗探针 ==");
        String probeA = base58(new byte[]{58});
        System.out.println("探针A base58(58)：期望\"21\" → 实际\"" + probeA + "\""
                + ("21".equals(probeA) ? "" : "，才怪嘞，余数0又被当成终止信号了"));
        String probeB = base58(new byte[]{0x00, 0x00, 0x7F});
        System.out.println("探针B base58(00 00 7F)：期望以\"11\"开头 → 实际\"" + probeB + "\""
                + (probeB.startsWith("11") ? "" : "，才怪嘞，前导零没有逐个补'1'"));


        // 实际生成的逻辑，而不是推导出公认向量：同一把随机私钥，一次推出三个链上合法地址
        BigInteger randomPrivateKey = new BigInteger(256, new SecureRandom()).mod(curve.getN());
        ECPoint randomPublicKey = curve.getG().multiply(randomPrivateKey).normalize();

        byte[] randomXY = Arrays.copyOfRange(randomPublicKey.getEncoded(false), 1, 65);
        byte[] randomHash = MessageDigest.getInstance("KECCAK-256", "BC").digest(randomXY);

        System.out.println("\n== 随机私钥走全程（同一把私钥、三个地址）==");
        System.out.println("随机私钥：" + HexFormat.of().formatHex(to32Bytes(randomPrivateKey)));
        System.out.println("ETH地址：0x" + HexFormat.of().formatHex(Arrays.copyOfRange(randomHash, 12, 32)));
        System.out.println("BTC地址(未压缩)：" + btcAddress(randomPublicKey, false));
        System.out.println("BTC地址(压缩)：" + btcAddress(randomPublicKey, true));

    }


    /**
     * 公钥点 → BTC P2PKH 地址。
     * compressed切换公钥编码：true=0x02/0x03+X共33字节，false=0x04+X+Y共65字节——
     * 同一把私钥由此产出两个都合法、互不相通的地址
     */
    static String btcAddress(ECPoint publicKey, boolean compressed) throws Exception {
        byte[] encoded = publicKey.getEncoded(compressed);
        byte[] sha256Digest = MessageDigest.getInstance("SHA-256").digest(encoded);
        byte[] ripemd160Digest = MessageDigest.getInstance("RIPEMD160", "BC").digest(sha256Digest);

        // 25字节布局：[0]版本0x00 [1..20]hash160 [21..24]校验和(对[0..20]双SHA-256取前4)
        byte[] address25 = new byte[25];
        address25[0] = 0x00;
        System.arraycopy(ripemd160Digest, 0, address25, 1, 20);
        byte[] checksum = MessageDigest.getInstance("SHA-256")
                .digest(MessageDigest.getInstance("SHA-256").digest(Arrays.copyOfRange(address25, 0, 21)));
        System.arraycopy(checksum, 0, address25, 21, 4);

        return base58(address25);
    }

    /**
     * 手写Base58：大数除58取余查表。
     * 入参必须是byte[]而不是BigInteger——前导零信息只存在于原始字节里(BigInteger会把它吃掉)，
     * 每个前导0x00单独转成一个'1'补在最前面
     */
    static String base58(byte[] data) {
        StringBuilder sb = new StringBuilder();
        BigInteger n = new BigInteger(1, data);
        // 终止条件是"数除完了"(商为零)；余数0是合法字符'1'，照常append
        while (n.signum() > 0) {
            BigInteger[] quotientAndRemainder = n.divideAndRemainder(BigInteger.valueOf(58));
            sb.append(STRING.charAt(quotientAndRemainder[1].intValue()));
            n = quotientAndRemainder[0];
        }
        // 前导零在"输入"上数，不在输出里找——Base58字符里永远没有0x00
        for (byte b : data) {
            if (b != 0x00) {
                break;
            }
            sb.append('1');
        }
        return sb.reverse().toString();
    }


    static byte[] to32Bytes(BigInteger n) {
        byte[] raw = n.toByteArray();
        if (raw.length == 32) {
            return raw;
        }
        byte[] out = new byte[32];
        if (raw.length > 32) {
            // 只可能多出前导符号零，砍头
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            // 不足则左补零
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

}
