package com.jeejio.lib;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;


public class RSA{
	 /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 245;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 256;

    /**
     * 获取密钥对
     * 
     * @return 密钥对
     */
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    /**
     * 获取私钥
     * 
     * @param privateKey 私钥字符串
     * @return
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.decodeBase64(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 获取公钥
     * 
     * @param publicKey 公钥字符串
     * @return
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.decodeBase64(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * RSA加密
     * 
     * @param data 待加密数据
     * @param publicKey 公钥
     * @return
     */
    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.getBytes().length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        //对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        // 获取加密内容使用base64进行编码,并以UTF-8为标准转化成字符串
        // 加密后的字符串
        return new String(Base64.encodeBase64String(encryptedData));
    }
    
    /**
     * RSA加密
     * 
     * @param data 待加密数据
     * @param privateKey 私钥
     * @return
     */
    public static String encrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        int inputLen = data.getBytes().length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        // 获取加密内容使用base64进行编码,并以UTF-8为标准转化成字符串
        // 加密后的字符串
        return new String(Base64.encodeBase64String(encryptedData));
    }

    /**
     * RSA解密
     * 
     * @param data 待解密数据
     * @param publicKey 公钥
     * @return
     */
    public static String decrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] dataBytes = Base64.decodeBase64(data);
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        // 解密后的内容 
        return new String(decryptedData, "UTF-8");
    }
    
    
    /**
     * RSA解密
     * 
     * @param data 待解密数据
     * @param privateKey 私钥
     * @return
     */
    public static String decrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] dataBytes = Base64.decodeBase64(data);
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        // 解密后的内容 
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 签名
     * 
     * @param data 待签名数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(key);
        signature.update(data.getBytes());
        return new String(Base64.encodeBase64(signature.sign()));
    }

    /**
     * 验签
     * 
     * @param srcData 原始字符串
     * @param publicKey 公钥
     * @param sign 签名
     * @return 是否验签通过
     */
    public static boolean verify(String srcData, PublicKey publicKey, String sign) throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(key);
        signature.update(srcData.getBytes());
        return signature.verify(Base64.decodeBase64(sign.getBytes()));
    }

    /*public static KeyStore loadKeystore(String path,String password){
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(path), password.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return keyStore;
    }*/

    public static KeyStore loadKeystore(String path,String password){
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("PKCS12");

            String keystoreData = readFile(path);
            if(keystoreData != null){
                keyStore.load(new ByteArrayInputStream(Base64.decodeBase64(keystoreData)), password.toCharArray());
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    public static String readFile(String path)throws IOException {

        FileInputStream fip = new FileInputStream(path);
        InputStreamReader reader = new InputStreamReader(fip, "UTF-8");
        StringBuffer sb = new StringBuffer();
        while(reader.ready()){
            //将读取的数据转化成char类型，加入StringBuffer对象sb里
            sb.append((char)reader.read());

        }
        //将sb对象内容转化成string类型，输出
        System.out.println(sb.toString());
        //关闭读取流
        reader.close();
        //关闭输入流，释放系统资源
        fip.close();
        return sb.toString();
    }


    public static void main(String[] args) {
        try {
            // 生成密钥对
            /*KeyPair keyPair = getKeyPair();
            String privateKey = new String(Base64.encodeBase64(keyPair.getPrivate().getEncoded()));
            String publicKey = new String(Base64.encodeBase64(keyPair.getPublic().getEncoded()));
            System.out.println("私钥:" + privateKey);
            System.out.println("公钥:" + publicKey);
            // RSA加密
            String data = "测试公钥加密私钥解密";
            String encryptData = encrypt(data, getPublicKey(publicKey));
            System.out.println("加密后内容:" + encryptData);
            // RSA解密
            String decryptData = decrypt(encryptData, getPrivateKey(privateKey));
            System.out.println("解密后内容:" + decryptData);

            // RSA签名
            String sign = sign(data, getPrivateKey(privateKey));
            System.out.println("签名结果:" + sign);
            // RSA验签
            boolean result = verify(data, getPublicKey(publicKey), sign);
            System.out.print("验签结果:" + result);*/

            String password = "123456";
            KeyStore keyStore = loadKeystore("/home/liyang/dev/keystore.p12",password);

            //私钥
            Enumeration aliases = keyStore.aliases();
            String keyAlias = null;
            if (aliases.hasMoreElements()){
                keyAlias = (String)aliases.nextElement();
                System.out.println("p12's alias----->"+keyAlias);
            }
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, password.toCharArray());
            String privateKeyStr = Base64.encodeBase64String(privateKey.getEncoded());
            System.out.println("私钥------------->" + privateKeyStr);

            //公钥
            Certificate certificate = keyStore.getCertificate(keyAlias);
            String publicKeyStr = Base64.encodeBase64String(certificate.getPublicKey().getEncoded());
            System.out.println("公钥------------->"+publicKeyStr);

            // RSA加密
            String data = "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";
//            String encryptData = encrypt(data, getPublicKey(publicKeyStr));
//            System.out.println("加密后内容:" + encryptData);
            // RSA解密
            String decryptData = decrypt(data, getPrivateKey(privateKeyStr));
            System.out.println("解密后内容:" + decryptData);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }
    }
}
