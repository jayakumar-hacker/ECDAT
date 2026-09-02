package com.acme.hrportal.security;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;

/**
 * HR Portal legacy security utilities.
 * Fictional demo code for ECDAT scanning purposes - intentionally contains
 * legacy/deprecated crypto usage typical of an older internal HR system.
 */
public class LegacySecurityUtils {

    // Legacy password hashing - SHA-1 is deprecated, kept here to demonstrate detection
    public static byte[] hashPasswordLegacy(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(password.getBytes());
    }

    // Old employee record encryption using DES - flagged for immediate retirement
    public static Cipher getLegacyCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    // RSA-2048 used for signing internal HR documents
    public static KeyPairGenerator getSigningKeyGenerator() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg;
    }

    // Newer AES-256 based encryption for recently added modules
    public static KeyGenerator getModernKeyGenerator() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg;
    }
}
