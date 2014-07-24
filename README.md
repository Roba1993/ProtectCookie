ProtectCookie
=============

This java framework protects html cookies against manipulating. The function is  inspired by the sessions from the play framework.


##Quick Start
```
//generate test cookies
cookies = new HashMap<String, String>();
cookies.put("Hello", "World");
cookies.put("Hallo", "Welt");

//secure the test cookies against modification
Map<String, String> secureCookies = ProtectCookie.secureCookies(cookies);

```
The secured cookies have the following structure:

|key | value |
|----|----|
|Hallo | Welt+J/0YpCOei3I3C5ewjZcCijnmLmtBj2PI1cF6/EUxkqPDdpiyRjq2bT1c7mpoXDjb|
|Hello | World+Q9cHW8/TIvOqFkwy10c+iZVnH82LuGPxIyvVB5sZsBBszP9Ll/y5Dn/wig7Ldqpt|

You are still able to see the default key and value. When you want to check if the key or value from the secured cookie is changed, call the following function.

```
//get cookies back
Map<String, String> cookies = ProtectCookie.unsecureCookies(secureCookies);
```

You always get the key from the cookie back. When a cookie is manipulated, you get the key from the cookie with a `null` value back. If the cookie isn't manipulated you get the original key and value back.