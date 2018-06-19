# clj-jwt

A really simple [JWT](https://jwt.io) library for generating and verifying JWT
tokens.

```
(require '[jwt :as jwt])
(def token (jwt/jwt {:payload "Hello World"} "key.pem" :rsassa-pss+sha256))
(def the-jwt (jwt/verify token "cert.pem"))
(when (get-in the-jwt [:signature :ok?])
  (println "Token is fine!"))
```

This library depends on *buddy-core* for digital signatures. You can find the
list of supported algorithms [here](https://funcool.github.io/buddy-core/latest/#digital-signatures).
