package io.github.sevenqi27.crypto.d04;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.io.File;
import java.security.SecureRandom;

/**
 * 企鹅图实验的实物版：把一张图的裸像素分别用 ECB 和 GCM 加密，再把密文当像素画回去。
 *
 * 原理：图片里大片同色区域 = 大量内容相同的 16 字节块。ECB 同块明文必出同块密文，
 * 所以"哪里是同一种颜色"这个结构信息原样保留——密钥没破、颜色全变，轮廓却看得见。
 * GCM（CTR 家族）每块的加密材料 = IV + 块序号，同色块也出不同密文 → 纯雪花。
 *
 * 期望：target/penguin/ecb.png 能认出企鹅轮廓；target/penguin/gcm.png 什么都认不出。
 */
public class EcbPenguinPicture {

    public static void main(String[] args) throws Exception {
        BufferedImage original = drawPenguin();

        // 取裸像素（3 字节一个像素的 BGR 数组）。注意：必须加密"裸像素"，
        // 如果先存成 PNG 再加密，PNG 的压缩早就把重复结构搅没了，实验不成立
        byte[] pixels = ((DataBufferByte) original.getRaster().getDataBuffer()).getData();

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey key = keyGen.generateKey();

        // ECB 加密像素
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        ecb.init(Cipher.ENCRYPT_MODE, key);
        byte[] ecbBytes = ecb.doFinal(pixels);

        // GCM 加密同一批像素
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] gcmBytes = gcm.doFinal(pixels);

        File dir = new File("target/penguin");
        dir.mkdirs();
        ImageIO.write(original, "png", new File(dir, "original.png"));
        ImageIO.write(toImage(ecbBytes, original), "png", new File(dir, "ecb.png"));
        ImageIO.write(toImage(gcmBytes, original), "png", new File(dir, "gcm.png"));

        System.out.println("三张图已生成在 " + dir.getAbsolutePath());
        System.out.println("期望：ecb.png 颜色全变但企鹅轮廓可辨；gcm.png 纯雪花，什么都认不出");
    }

    /** 把密文字节塞回同尺寸画布当像素（密文比明文长一点点，截断到画布容量即可） */
    private static BufferedImage toImage(byte[] cipherBytes, BufferedImage sizeRef) {
        BufferedImage img = new BufferedImage(sizeRef.getWidth(), sizeRef.getHeight(), BufferedImage.TYPE_3BYTE_BGR);
        byte[] target = ((DataBufferByte) img.getRaster().getDataBuffer()).getData();
        System.arraycopy(cipherBytes, 0, target, 0, target.length);
        return img;
    }

    /** 手绘一只糙版企鹅：要点是大片纯色区域，这正是 ECB 藏不住的东西 */
    private static BufferedImage drawPenguin() {
        BufferedImage img = new BufferedImage(384, 448, BufferedImage.TYPE_3BYTE_BGR);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_OFF);
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 384, 448);            // 背景
        g.setColor(Color.BLACK);
        g.fillOval(92, 120, 200, 290);          // 身体
        g.fillOval(132, 40, 120, 130);          // 头
        g.setColor(Color.WHITE);
        g.fillOval(122, 190, 140, 200);         // 肚皮
        g.fillOval(152, 75, 28, 36);            // 左眼
        g.fillOval(204, 75, 28, 36);            // 右眼
        g.setColor(Color.BLACK);
        g.fillOval(162, 88, 10, 14);            // 左眼珠
        g.fillOval(212, 88, 10, 14);            // 右眼珠
        g.setColor(Color.ORANGE);
        g.fillPolygon(new int[]{172, 212, 192}, new int[]{118, 118, 145}, 3); // 嘴
        g.fillOval(120, 400, 60, 26);           // 左脚
        g.fillOval(204, 400, 60, 26);           // 右脚
        g.dispose();
        return img;
    }
}
