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
 * demo 05 样例：ETH 地址推导（私钥 → 公钥点 → Keccak-256 → 后20字节 → 0x hex）。
 *
 * 地址不是新密码学：就是"公钥 → 哈希 → 编码"三步，BTC/ETH 只是选了不同的哈希和编码。
 * 本样例走通 ETH 线并用全网公认测试向量(私钥=1)当独立裁判；BTC 线（SHA256→RIPEMD160、
 * 版本字节+双SHA256校验和、手写Base58、压缩/未压缩两地址探针）照这个骨架自己写。
 */
public class EthAddressSample {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        HexFormat hex = HexFormat.of();

        // ===== 探针0：先排雷——Keccak-256 和 SHA3-256 不是一个东西 =====
        // 以太坊用的是 NIST 标准化之前的 Keccak 原版，定稿时改了一个 padding 字节。
        // 空串的两个哈希值网上都能查到标准答案，可独立核对：
        //   KECCAK-256("") = c5d2460186f7...    SHA3-256("") = a7ffc6f8bf1e...
        byte[] keccakEmpty = MessageDigest.getInstance("KECCAK-256", "BC").digest(new byte[0]);
        byte[] sha3Empty = MessageDigest.getInstance("SHA3-256").digest(new byte[0]);
        System.out.println("== 探针0：Keccak vs SHA3 ==");
        System.out.println("KECCAK-256(\"\") = " + hex.formatHex(keccakEmpty));
        System.out.println("SHA3-256(\"\")   = " + hex.formatHex(sha3Empty));
        System.out.println("期望：两者不同，KECCAK 以 c5d24601 开头 → 实际：" +
                (hex.formatHex(keccakEmpty).startsWith("c5d24601") && !Arrays.equals(keccakEmpty, sha3Empty)
                        ? "命中，ETH 必须用 KECCAK-256" : "才怪嘞，跟公开向量对不上？"));

        // ===== 第一步：私钥。它就是一个 256 位的数，没有任何结构 =====
        // 私钥=1 是全世界公认的测试向量（公钥恰好就是 G 本身），用它当独立裁判
        BigInteger privateKey = BigInteger.ONE;

        // ===== 第二步：公钥 Q = d×G —— demo01 那扇单向门的正向通行，就这一行 =====
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint publicKey = curve.getG().multiply(privateKey).normalize();

        // ===== 第三步：取公钥字节。ETH 用 X‖Y 共 64 字节（去掉 0x04 前缀）=====
        // 坑2现场：BigInteger.toByteArray() 可能 33 字节(带符号位)或不足 32 字节(高位为零)，
        // 必须自己左补零对齐——见 to32Bytes()
        byte[] x = to32Bytes(publicKey.getAffineXCoord().toBigInteger());
        byte[] y = to32Bytes(publicKey.getAffineYCoord().toBigInteger());
        byte[] xy = new byte[64];
        System.arraycopy(x, 0, xy, 0, 32);
        System.arraycopy(y, 0, xy, 32, 32);

        // 自检：getEncoded(false) 给的是 0x04‖X‖Y 共 65 字节，去头应与手拼的 64 字节一致
        byte[] encoded = publicKey.getEncoded(false);
        System.out.println("\n== 自检：手拼 X‖Y vs getEncoded(false) 去掉 0x04 头 ==");
        System.out.println("期望true：" + Arrays.equals(xy, Arrays.copyOfRange(encoded, 1, 65))
                + "（顺带确认：encoded[0] = 0x" + String.format("%02x", encoded[0]) + "，demo04 见过的老朋友）");

        // ===== 第四步：Keccak-256 哈希，取"后"20 字节 =====
        byte[] hash = MessageDigest.getInstance("KECCAK-256", "BC").digest(xy);
        byte[] addressBytes = Arrays.copyOfRange(hash, 12, 32);

        // ===== 第五步：编码。ETH 最朴素：0x + hex =====
        String address = "0x" + hex.formatHex(addressBytes);
        System.out.println("\n== 私钥=1 的 ETH 地址（独立裁判对表）==");
        System.out.println("推导结果：" + address);
        String wellKnown = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        System.out.println("公认向量：" + wellKnown);
        System.out.println("期望一致 → 实际：" + (address.equals(wellKnown) ? "一致，流水线全对" : "才怪嘞，某一步错了"));

        // ===== 附赠：随机私钥走一遍全程——一个真正"从数学推出来"的钱包地址 =====
        BigInteger randomKey = new BigInteger(256, new SecureRandom()).mod(curve.getN());
        ECPoint randomPub = curve.getG().multiply(randomKey).normalize();
        byte[] randomXy = Arrays.copyOfRange(randomPub.getEncoded(false), 1, 65);
        byte[] randomHash = MessageDigest.getInstance("KECCAK-256", "BC").digest(randomXy);
        System.out.println("\n== 随机私钥全程 ==");
        System.out.println("私钥：" + hex.formatHex(to32Bytes(randomKey)));
        System.out.println("地址：0x" + hex.formatHex(Arrays.copyOfRange(randomHash, 12, 32)));
        System.out.println("（这个地址现在就能在 etherscan 上查——余额为 0，但它是链上合法的收款地址）");
    }

    /**
     * 坑2的修法：BigInteger 定长对齐到 32 字节。
     * toByteArray() 是补码表示——最高位是 1 时会多出一个 0x00 符号字节(33字节)，
     * 数值小时又不足 32 字节，两种情况都要处理
     */
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
