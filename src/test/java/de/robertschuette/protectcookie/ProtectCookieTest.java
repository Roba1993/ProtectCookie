package de.robertschuette.protectcookie;

import java.util.HashMap;
import java.util.Map;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Schütte
 */
public class ProtectCookieTest {

    Map<String, String> cookies;

    @Before
    public void setUp() {
        cookies = new HashMap<String, String>();
        cookies.put("Hallo", "Welt");
        cookies.put("Hello", "World");
        cookies.put("Robert", "Schütte");
        cookies.put("email", "mail@robertschuette.de");
        cookies.put("login", "true");
    }

    @Test
    public void simpleCookieTest() {
        ProtectCookie pc = new ProtectCookie();
        
        //secure the cookies
        Map<String, String> secure = pc.secureCookies(cookies);

        //secured must be different from unsecured
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            assertNotSame(entry.getValue(), secure.get(entry.getKey()));
        }

        //unsecure the cookies
        Map<String, String> unsecure = pc.unsecureCookies(secure);

        //check if the unsecured cookies the same as the input
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            assertEquals(entry.getValue(), unsecure.get(entry.getKey()));
        }
    }

    @Test
    public void changeCookieTest() {
        ProtectCookie pc = new ProtectCookie();
        
        //secure the cookies
        Map<String, String> secure = pc.secureCookies(cookies);

        //change first two letters
        for (Map.Entry<String, String> entry : secure.entrySet()) {
            entry.setValue(entry.getValue().substring(2));
        }

        //unsecure the cookies
        Map<String, String> unsecure = pc.unsecureCookies(secure);

        //check if the unsecured cookies the same as the input
        for (Map.Entry<String, String> entry : unsecure.entrySet()) {
            assertNull("is change must be null", entry.getValue());
        }
    }
}
