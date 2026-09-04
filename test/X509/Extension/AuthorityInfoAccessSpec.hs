{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.AuthorityInfoAccessSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.X509.XT.AuthorityInfoAccess'.
-}
module X509.Extension.AuthorityInfoAccessSpec (spec) where

import qualified Data.ByteString as BS
import Data.X509.XT (renderOpenSSLConfig)
import Data.X509.XT.AuthorityInfoAccess
import Data.X509.XT.GeneralName
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll)
import Text.URI (mkURI)
import X509.Extension.Fixtures (assertRight)
import X509.Extension.Generators (validDnsName)


spec :: Spec
spec = describe "module Data.X509.XT.AuthorityInfoAccess" $ do
  context "mkAuthorityInfoAccess" $ do
    it "renders a single OCSP entry" $ do
      uri <- mkURI "http://ocsp.example.com"
      renderOpenSSLConfig (mkAuthorityInfoAccess (OCSP (URIName uri)) [])
        `shouldBe` "OCSP;URI:http://ocsp.example.com"
    it "renders a single CAIssuers entry" $ do
      uri <- mkURI "http://ca.example.com/issuer.crt"
      renderOpenSSLConfig (mkAuthorityInfoAccess (CAIssuers (URIName uri)) [])
        `shouldBe` "caIssuers;URI:http://ca.example.com/issuer.crt"
    it "renders OCSP and CAIssuers together" $ do
      ocspUri   <- mkURI "http://ocsp.example.com"
      issuerUri <- mkURI "http://ca.example.com/issuer.crt"
      renderOpenSSLConfig
        ( mkAuthorityInfoAccess
            (OCSP (URIName ocspUri))
            [CAIssuers (URIName issuerUri)]
        )
        `shouldBe` "OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://ca.example.com/issuer.crt"
    it "renders an Other name as OCSP location" $ do
      gn <- assertRight (mkOther 1 [2, 3] UTF8String "value")
      renderOpenSSLConfig (mkAuthorityInfoAccess (OCSP gn) [])
        `shouldBe` "OCSP;otherName:1.2.3;UTF8:value"
    prop "OCSP entries always start with OCSP;" $
      forAll validDnsName $ \dn ->
        BS.isPrefixOf "OCSP;" (renderOpenSSLConfig (mkAuthorityInfoAccess (OCSP (DNS dn)) []))
    prop "CAIssuers entries always start with caIssuers;" $
      forAll validDnsName $ \dn ->
        BS.isPrefixOf "caIssuers;" (renderOpenSSLConfig (mkAuthorityInfoAccess (CAIssuers (DNS dn)) []))
