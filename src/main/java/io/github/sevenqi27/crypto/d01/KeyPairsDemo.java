package io.github.sevenqi27.crypto.d01;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

/**
 * Demo 01 — Key pairs: what a public/private key pair actually is.
 * Demo 01 — 密钥对：公钥/私钥到底是什么。
 *
 * Two families side by side:
 * 两大算法家族并排对比：
 *
 *   RSA — one-way door: multiplying two big primes is instant,
 *         factoring the product back is infeasible.
 *   RSA — 单向门是"颜料混合"：两个大质数相乘一瞬间，把乘积拆回去不可行。
 *
 *   EC  — one-way door: hopping d times from the base point G is fast
 *         (double-and-add), counting the hops from the landing point is infeasible.
 *   EC  — 单向门是"弹珠台"：从起点 G 跳 d 次很快（倍加法），看着落点数出跳了几次不可行。
 *
 * The one idea to take away: the public key is DERIVED from the private key —
 * cheap in one direction, infeasible to reverse.
 * 本课唯一要带走的思想：公钥是从私钥"派生"出来的——正向计算便宜，反向推导不可行。
 */
public class KeyPairsDemo {

    public static void main(String[] args) throws Exception {
        // Java crypto (JCA) is a socket-and-plug architecture: the JDK defines
        // interfaces and factories (sockets), actual algorithm implementations
        // come from "Providers" (plugs). This line plugs BouncyCastle in.
        // Java 密码学体系（JCA）是"插座-插头"结构：JDK 只定义接口和工厂（插座），
        // 具体算法实现由 Provider（插头）提供。这一行就是把 BouncyCastle 插进去。
        //
        // Why BC is a must here:
        // 为什么必须用 BC，两个原因：
        //   1. The default JDK provider REMOVED secp256k1 (since JDK 15) — but that
        //      is exactly the Bitcoin/Ethereum curve. For blockchain work in Java,
        //      BC is the de-facto standard.
        //      JDK 自带实现从 JDK 15 起移除了 secp256k1——而它恰恰是比特币/以太坊的曲线。
        //      在 Java 里玩链上密码学，BC 几乎是标配。
        //   2. BC exposes the curve point MATH (ECPoint.multiply etc.). The JDK only
        //      lets you USE keys, never touch the math inside — and touching the
        //      math is the whole point of this demo.
        //      BC 暴露了曲线点的数学运算接口（ECPoint.multiply 等）。JDK 只让你"用"密钥，
        //      不让你"摸"里面的数学——而摸数学正是这个 demo 的目的。
        Security.addProvider(new BouncyCastleProvider());

        rsaKeyPair();
        ecKeyPair();
        derivePublicFromPrivate();
    }

    static void rsaKeyPair() throws Exception {
        System.out.println("=== 1. RSA 2048 key pair ===");

        // getInstance(algorithm, provider) — factory method, JCA-standard algorithm
        // name string. The second argument "BC" FORCES the BouncyCastle
        // implementation. Without it, Java picks whichever provider has the highest
        // priority (usually the JDK's own SunRsaSign) — a real production pitfall:
        // same code, different JDK, different implementation.
        // getInstance(算法名, provider) —— 工厂方法，第一个参数是 JCA 标准算法名字符串。
        // 第二个参数 "BC" 强制使用 BouncyCastle 实现。不写的话 Java 按 Provider 优先级
        // 自动挑（通常是 JDK 自带的 SunRsaSign）——生产环境的真实坑：
        // 同一份代码在不同 JDK 环境可能走了不同实现。
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");

        // initialize(keysize, random) — two deliberate choices here:
        // initialize(位数, 随机源) —— 两个参数都有讲究：
        //
        // Why 2048: this is the bit length of the modulus n (the "mixed paint").
        //   1024 — considered breakable, banned by standards since ~2013;
        //   2048 — current baseline, considered safe until ~2030;
        //   4096 — safer but private-key operations get ~6-8x slower.
        // 为什么是 2048：这是模数 n（"混合后的颜料"）的位数。
        //   1024 —— 已被认为可破解，2013 年前后被各标准禁用；
        //   2048 —— 当前基线，普遍认为安全到 2030 年左右；
        //   4096 —— 更安全，但私钥运算慢 6-8 倍，多数场景不划算。
        //
        // Why SecureRandom, never java.util.Random: Random is deterministic — same
        // seed, same sequence. If your randomness is guessable, your PRIVATE KEY is
        // guessable; the key is only as secret as the entropy that made it.
        // SecureRandom draws from OS entropy (/dev/urandom). Real-world lesson:
        // Android's broken SecureRandom in 2013 let attackers recompute Bitcoin
        // wallet keys and steal funds.
        // 为什么用 SecureRandom 而绝不能用 java.util.Random：Random 是确定性的——
        // 种子相同、序列就相同。随机数可预测 = 私钥可预测；
        // 密钥的保密程度，本质上等于生成它的那把随机数的质量。
        // SecureRandom 从操作系统熵池（/dev/urandom）取随机。真实案例：
        // 2013 年 Android 的 SecureRandom 缺陷导致比特币钱包私钥被重算、资金被盗。
        gen.initialize(2048, new SecureRandom());
        KeyPair kp = gen.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

        System.out.println("modulus n bit length : " + pub.getModulus().bitLength());

        // You will almost always see e = 65537 (0x10001). Why this magic number:
        // it is prime, and in binary it is 1_0000000000000001 — only two 1-bits,
        // which makes public-key operations (encrypt/verify) very fast, while being
        // large enough to dodge the classic small-exponent (e=3) attacks.
        // 公钥指数 e 几乎永远是 65537（0x10001）。为什么是这个魔法数字：
        // 它是质数，且二进制是 1_0000000000000001——只有两个 1，
        // 让公钥运算（加密/验签）非常快；同时又足够大，避开了 e=3 的小指数攻击。
        System.out.println("public exponent e    : " + pub.getPublicExponent());

        // Both halves share the same modulus n; the private exponent d is the secret.
        // Whoever factors n back into p and q can compute d — that is the whole game.
        // 公钥和私钥共享同一个模数 n，真正保密的是私钥指数 d。
        // 谁能把 n 分解回 p 和 q，谁就能算出 d——整个 RSA 的安全性就押在这一件事上。
        System.out.println("same modulus in both : " + pub.getModulus().equals(priv.getModulus()));
        System.out.println();
    }

    static void ecKeyPair() throws Exception {
        System.out.println("=== 2. EC secp256k1 key pair (Bitcoin/Ethereum curve) ===");

        // Algorithm name is just "EC" — which CURVE you want is a separate choice,
        // passed via ECGenParameterSpec below.
        // 算法名只写 "EC"——具体用哪条曲线是另一个独立选择，由下面的 ECGenParameterSpec 传入。
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");

        // "secp256k1" decoded: SEC standard / p = prime field / 256-bit / k = Koblitz
        // family / version 1. Its sibling secp256r1 ("r" = random) is what TLS and
        // most CAs use; China's SM2 is also an EC curve of the same shape.
        // Bitcoin chose k1; the math is identical, only the curve constants differ.
        // "secp256k1" 逐段解读：SEC 标准 / p=素数域 / 256 位 / k=Koblitz 家族 / 版本 1。
        // 它的兄弟 secp256r1（r=random）是 TLS 和多数 CA 在用的；国密 SM2 本质上也是
        // 同一形态的椭圆曲线。比特币选了 k1；数学完全一样，只是曲线常数不同。
        //
        // Why a NAMED curve instead of custom parameters: curve constants are
        // extremely easy to get wrong (weak curves exist), and interop requires
        // everyone to use the same ones. Rule of thumb: never invent your own curve.
        // 为什么用"具名曲线"而不是自定义参数：曲线常数极易选错（存在弱曲线），
        // 而且互操作要求全世界用同一组常数。行业铁律：永远不要自己发明曲线。
        gen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        KeyPair kp = gen.generateKeyPair();

        org.bouncycastle.jce.interfaces.ECPrivateKey priv =
                (org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate();
        org.bouncycastle.jce.interfaces.ECPublicKey pub =
                (org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic();

        // getD() — the private key really is just this one big integer d
        // (the "number of hops" on the pinball table). toString(16) prints hex,
        // because that is how the industry displays keys: a Bitcoin/Ethereum
        // private key you have seen in a wallet is exactly this, 64 hex chars.
        // getD() —— 私钥真的就只是这一个大整数 d（弹珠台上"跳的次数"）。
        // toString(16) 转十六进制打印，因为行业惯例就是这么展示密钥：
        // 你在钱包里见过的比特币/以太坊私钥，就是这个数字的 64 个十六进制字符。
        System.out.println("private scalar d     : " + priv.getD().toString(16));

        // getQ() — the public key is a POINT (x, y) on the curve, not a number.
        // normalize(): internally BC stores points in projective coordinates
        // (a trick that avoids slow division during point math); normalize()
        // converts back to the plain affine (x, y) so we can read and compare.
        // getQ() —— 公钥不是一个数，而是曲线上的一个"点" (x, y)。
        // normalize()：BC 内部用"射影坐标"存点（一种运算时避免慢速除法的加速技巧），
        // normalize() 把它换算回普通的仿射坐标 (x, y)，才能拿来阅读和比较。
        System.out.println("public point Q.x     : " + pub.getQ().normalize().getXCoord());
        System.out.println("public point Q.y     : " + pub.getQ().normalize().getYCoord());
        System.out.println();
    }

    /**
     * The money shot: recompute the public key from the private key by hand.
     * Q = d * G, where G is the fixed generator point of the curve.
     * 压轴戏：亲手从私钥重新推导出公钥。Q = d * G，G 是曲线公认的固定起点（生成元）。
     *
     * This is the exact operation a wallet performs when it derives an address
     * from a freshly generated private key.
     * 钱包从新生成的私钥推导地址时，执行的就是这一步运算。
     */
    static void derivePublicFromPrivate() throws Exception {
        System.out.println("=== 3. Deriving the public key: Q = d * G ===");

        // ECNamedCurveTable is BC's built-in registry of named curves. The returned
        // spec is the full constant bundle for secp256k1: field prime p, curve
        // coefficients a and b, generator point G, group order n, cofactor h.
        // We fetch it because we need G — the world-shared starting point.
        // ECNamedCurveTable 是 BC 内置的"具名曲线登记簿"。返回的 spec 是 secp256k1 的
        // 全套常数包：素数域 p、曲线系数 a 和 b、生成元 G、阶 n、余因子 h。
        // 取它的目的只有一个：拿到 G——那个全世界共用的起点。
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        KeyPair kp = gen.generateKeyPair();

        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getD();
        ECPoint qFromKey = ((org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic()).getQ().normalize();

        // multiply(d) — scalar multiplication, the "hop d times" operation.
        // It does NOT hop one by one: it uses double-and-add (same idea as fast
        // exponentiation): from "position after 4 hops" it jumps straight to
        // "position after 8 hops". A 256-bit d takes only a few hundred steps.
        // Forward: a few hundred steps. Backward (find d from Q): try 2^256
        // possibilities. That asymmetry IS the private/public key relationship.
        // multiply(d) —— 标量乘法，就是"跳 d 次"这个动作。
        // 它并不真的一次次跳：用的是"倍加法"（和快速幂同一个思想）——
        // 从"跳了 4 次的落点"直接翻倍到"跳了 8 次的落点"。
        // 256 位的 d 只需要几百步就算完。
        // 正向：几百步。反向（由 Q 反推 d）：试 2^256 种可能。
        // 这个不对称性，就是公钥/私钥关系的全部本质。
        ECPoint qComputed = spec.getG().multiply(d).normalize();

        System.out.println("Q from generated key : " + qFromKey.getXCoord());
        System.out.println("Q computed as d * G  : " + qComputed.getXCoord());

        // equals() compares the full point (both coordinates), not just the
        // printed x — printing x alone is just to keep the output short.
        // equals() 比较的是完整的点（两个坐标都比），不只是打印出来的 x——
        // 上面只打印 x 纯粹是为了输出简短。
        System.out.println("identical            : " + qFromKey.equals(qComputed));
    }
}
