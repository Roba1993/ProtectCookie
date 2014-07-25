package de.robertschuette.protectcookie;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.text.BasicTextEncryptor;

/**
 *
 * @author Robert Schütte
 */
public class ProtectCookie {

    private static final BasicPasswordEncryptor passwordEncryptor = new BasicPasswordEncryptor();
    private static BasicTextEncryptor textEncryptor;
    private static String privateKey;

    /**
     * This function secures a map of cookies against modification.
     *
     * @param cookies The unsecured cookies
     * @return The secured cookies
     */
    public static Map<String, String> secureCookies(Map<String, String> cookies) {
        //we need a private key
        checkPrivateKey();

        //Return map
        HashMap<String, String> out = new HashMap<String, String>();

        //cookies in the map?
        if (cookies == null || cookies.isEmpty()) {
            return out;
        }

        //loop all cookies
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            //secure each cookie
            out.put(entry.getKey(), generateProtectedCookie(entry.getKey(), entry.getValue()));
        }

        //give all cookies back
        return out;
    }

    /**
     * This function checks if the cookies are modified or not. When a cookie is
     * modified, his value will be set to null.
     *
     * @param cookies
     * @return
     */
    public static Map<String, String> unsecureCookies(Map<String, String> cookies) {
        //we need a private key
        checkPrivateKey();

        //Return map
        HashMap<String, String> out = new HashMap<String, String>();

        //cookies in the map?
        if (cookies == null || cookies.isEmpty()) {
            return out;
        }

        //loop all cookies
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            //unsecure each cookie
            out.put(entry.getKey(), generateUnprotectedCookie(entry.getKey(), entry.getValue()));
        }

        //give all cookies back
        return out;
    }

    /**
     * This function secures one Cookie. The return value is the new secured
     * value. The given key is also secured and can't changed after this
     * function.
     *
     * @param key coookie key
     * @param value cookie value
     * @return secured cookie value
     */
    public static String secureCookie(String key, String value) {
        return generateProtectedCookie(key, value);
    }

    /**
     * This function secures one Cookie. The return value is the new unsecured
     * value. When there was change in the key or value, the returnd value is
     * null.
     *
     * @param key cookie key
     * @param value secured cookie value
     * @return unsecured cookie value
     */
    public static String unsecureCookie(String key, String value) {
        return generateUnprotectedCookie(key, value);
    }

    /**
     * This function set's the privateKey for this application. The privateKey
     * is used to encrypt the cookies and save them against modification.
     *
     * @param privateKey
     */
    public static void setPrivateKey(String privateKey) {
        ProtectCookie.privateKey = privateKey;
        textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(privateKey);
    }

    //Private functions
    /**
     * This functions checks if a privateKey exist. If not the fucntion creates
     * a new random private key.
     */
    private static void checkPrivateKey() {
        //generate a new random key if not exist
        if (privateKey == null) {

            //available key symbols
            String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int len = 32;

            //SecureRandom protectd against vulnerable to timing attacks
            SecureRandom rnd = new SecureRandom();

            //generate new random key
            StringBuilder sb = new StringBuilder(len);
            for (int i = 0; i < len; i++) {
                sb.append(AB.charAt(rnd.nextInt(AB.length())));
            }

            //set the key and create a textEncryptor
            setPrivateKey(sb.toString());
        }
    }

    /**
     * This function protect a single cookie value.
     *
     * @param name
     * @param value
     * @return
     */
    private static String generateProtectedCookie(String name, String value) {
        //no null values allowed
        if (name == null || value == null) {
            return null;
        }

        //unmask all +
        value = value.replaceAll("\\+", "&#43;");

        //we hash the name and value to check if anyone change something
        String hash = passwordEncryptor.encryptPassword(name + "+" + value);

        //enrypt the hash to protect it against changes
        String crypt = textEncryptor.encrypt(hash);

        //return the name + value + secured hash
        return value + "+" + crypt;
    }

    /**
     * This function unprotect a single cookie value.
     *
     * @param name
     * @param value
     * @return
     */
    private static String generateUnprotectedCookie(String name, String value) {
        if (name == null || value == null) {
            return null;
        }

        //split the value to value and hash
        String split[] = value.split("\\+", 2);

        //we need the value and hash
        if (split.length != 2) {
            return null;
        }

        value = split[0];
        String hash = split[1];

        //get the old hash with decryption
        hash = textEncryptor.decrypt(hash);

        //when the hash's are equals no one has modified them and we can use them
        if (passwordEncryptor.checkPassword(name + "+" + value, hash)) {
            return value;
        }

        return null;
    }
}
