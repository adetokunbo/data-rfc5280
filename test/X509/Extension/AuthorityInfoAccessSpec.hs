{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.AuthorityInfoAccessSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.AuthorityInfoAccess'.
-}
module X509.Extension.AuthorityInfoAccessSpec (spec) where

import DataType.X509.Extension (asByteString)
import DataType.X509.Extension.AuthorityInfoAccess
import DataType.X509.Extension.GeneralName
import Test.Hspec
import Text.URI (mkURI)


spec :: Spec
spec = describe "module DataType.X509.Extension.AuthorityInfoAccess" $ do
  context "mkAuthorityInfoAccess" $ do
    it "renders a single OCSP entry" $ do
      uri <- mkURI "http://ocsp.example.com"
      asByteString (mkAuthorityInfoAccess (OCSP (URIName uri)) [])
        `shouldBe` "OCSP;URI:http://ocsp.example.com"
    it "renders a single CAIssuers entry" $ do
      uri <- mkURI "http://ca.example.com/issuer.crt"
      asByteString (mkAuthorityInfoAccess (CAIssuers (URIName uri)) [])
        `shouldBe` "caIssuers;URI:http://ca.example.com/issuer.crt"
    it "renders OCSP and CAIssuers together" $ do
      ocspUri    <- mkURI "http://ocsp.example.com"
      issuerUri  <- mkURI "http://ca.example.com/issuer.crt"
      asByteString
        ( mkAuthorityInfoAccess
            (OCSP (URIName ocspUri))
            [CAIssuers (URIName issuerUri)]
        )
        `shouldBe` "OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://ca.example.com/issuer.crt"
