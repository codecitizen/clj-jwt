(ns jwt
  (:require [clojure.data.codec.base64 :as b64]
            [clojure.data.json :as json]
            [clojure.string :refer [split]]
            [buddy.core.keys :as keys]
            [buddy.core.dsa :as dsa]
            [clojure.set :refer [map-invert]]))

(def alg-map {"PS256" :rsassa-pss+sha256
              "PS384" :rsassa-pss+sha384
              "PS512" :rsassa-pss+sha512
              "ES256" :ecdsa+sha256
              "ES384" :ecdsa+sha384
              "ES512" :ecdsa+sha512})

(def reverse-alg-map (map-invert alg-map))

(defn encode-component [component]
  (-> (json/write-str component)
      (.getBytes)
      (b64/encode)
      (String.)))

(defn sign [payload key-file algorithm]
  (-> (dsa/sign payload {:key (keys/private-key key-file) :alg algorithm})
      (b64/encode)
      (String.)))

(defn jwt [payload key-file algorithm]
  (let [header (encode-component {:alg (get reverse-alg-map algorithm)
                                  :typ "JWT"})
        payload (encode-component payload)
        signature (sign (str header "." payload) key-file algorithm)]
    (str header "." payload "." signature)))

(defn parse-component [component]
  (-> (.getBytes component)
      (b64/decode)
      (String.)
      (json/read-str :key-fn keyword)))

(defn decode-signature [signature]
  (-> (.getBytes signature)
      (b64/decode)))

(defn verify-signature [payload signature algorithm key-file]
  (let [public-key (keys/public-key key-file)]
    (dsa/verify payload
                (decode-signature signature)
                {:key public-key :alg (get alg-map algorithm)})))

(defn verify [token key-file]
  (let [components (split token #"\.")
        header (parse-component (first components))
        payload (parse-component (second components))
        signature (last components)]
    {:header header
     :payload payload
     :signature {:ok? (verify-signature
                       (str (first components) "." (second components))
                       signature
                       (:alg header)
                       key-file)
                 :value signature}}))
