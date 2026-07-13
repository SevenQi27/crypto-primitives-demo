package io.github.sevenqi27.crypto.d04;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * ECB 重复块探针（字符版企鹅图）。
 *
 * 公理：确定性就是泄漏——同样的输入两次产生同样的输出，攻击者就学到了"这两次是同一个东西"。
 * ECB 是"新鲜随机性入口 = 无"的对照组：无 IV、块间无联系，同块明文必出同块密文。
 *
 * 实验清单：
 *   1. Cipher.getInstance("AES") 默认模式加密重复明文 → 期望密文出现整行重复（结构裸奔）
 *   2. 同一明文 ECB 加密两遍 → 期望两次密文完全一致（确定性加密，连"发过两次"都藏不住）
 *   3. 同一明文换 GCM 加密 → 期望没有任何两块相同（IV+计数器抹掉了结构）
 *   4. 同一明文 GCM 加密两遍（各自新 IV）→ 期望两次密文完全不同
 */
public class EcbPatternProbe {

    public static void main(String[] args) throws Exception {
        // 构造带重复的明文：16 个 A 一块，重复 4 遍 = 64 字节，正好 4 个整块
        byte[] plaintext = "AAAAAAAAAAAAAAAA".repeat(4).getBytes(StandardCharsets.UTF_8);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey key = keyGen.generateKey();

        // 实验1：默认模式（SunJCE 补全为 AES/ECB/PKCS5Padding），注意 init 没有 IV 的入口
        Cipher ecb = Cipher.getInstance("AES");
        ecb.init(Cipher.ENCRYPT_MODE, key);
        byte[] ecbCiphertext = ecb.doFinal(plaintext);
        System.out.println("== 实验1：ECB 加密 64 字节重复明文，按 16 字节一行打印 ==");
        printBlocks(ecbCiphertext);
        System.out.println("期望：前 4 行完全相同 + 第 5 行不同（PKCS5 对整倍数明文额外补了一整块 padding）");
        boolean leaked = countDistinctBlocks(ecbCiphertext) == 2 && ecbCiphertext.length == 80;
        System.out.println("实际：不同的块数 = " + countDistinctBlocks(ecbCiphertext)
                + "，密文长度 = " + ecbCiphertext.length + " 字节 → " + (leaked ? "结构裸奔，实锤" : "才怪嘞，ECB 竟然没漏？"));

        // 实验2：同一明文再加密一遍，密文应一模一样
        Cipher ecbAgain = Cipher.getInstance("AES");
        ecbAgain.init(Cipher.ENCRYPT_MODE, key);
        byte[] ecbCiphertext2 = ecbAgain.doFinal(plaintext);
        System.out.println("\n== 实验2：同一明文 ECB 加密两遍 ==");
        System.out.println("期望：完全一致（没有随机性入口，加密是确定性的）");
        System.out.println("实际：两次密文是否一致 = " + Arrays.equals(ecbCiphertext, ecbCiphertext2));

        // 实验3：同一明文换 GCM，重复结构应被抹平
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] gcmCiphertext = gcm.doFinal(plaintext);
        System.out.println("\n== 实验3：同一明文改用 GCM，按 16 字节一行打印 ==");
        printBlocks(gcmCiphertext);
        System.out.println("期望：没有任何两行相同（最后 16 字节是认证 tag，不是数据块）");
        int gcmBlocks = (gcmCiphertext.length + 15) / 16;
        boolean noRepeat = countDistinctBlocks(gcmCiphertext) == gcmBlocks;
        System.out.println("实际：" + gcmBlocks + " 块里不同的块数 = " + countDistinctBlocks(gcmCiphertext)
                + " → " + (noRepeat ? "结构被抹平" : "才怪嘞，GCM 也出重复块了？"));

        // 实验4：GCM 加密两遍（各自新 IV），两次密文应完全不同
        byte[] iv2 = new byte[12];
        new SecureRandom().nextBytes(iv2);
        Cipher gcmAgain = Cipher.getInstance("AES/GCM/NoPadding");
        gcmAgain.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv2));
        byte[] gcmCiphertext2 = gcmAgain.doFinal(plaintext);
        System.out.println("\n== 实验4：同一明文 GCM 加密两遍（各自新 IV）==");
        System.out.println("期望：完全不同（每次一把新鲜 IV，同一封信两次上路长得也不一样）");
        System.out.println("实际：两次密文是否一致 = " + Arrays.equals(gcmCiphertext, gcmCiphertext2));
    }

    /** 每 16 字节（一个 AES 块）打印一行 Hex，重复块肉眼直接对齐 */
    private static void printBlocks(byte[] data) {
        HexFormat hex = HexFormat.of();
        for (int i = 0; i < data.length; i += 16) {
            byte[] block = Arrays.copyOfRange(data, i, Math.min(i + 16, data.length));
            System.out.printf("块%d: %s%n", i / 16 + 1, hex.formatHex(block));
        }
    }

    /** 数一数有多少个互不相同的 16 字节块 */
    private static long countDistinctBlocks(byte[] data) {
        HexFormat hex = HexFormat.of();
        return java.util.stream.IntStream.iterate(0, i -> i < data.length, i -> i + 16)
                .mapToObj(i -> hex.formatHex(Arrays.copyOfRange(data, i, Math.min(i + 16, data.length))))
                .distinct().count();
    }
}
