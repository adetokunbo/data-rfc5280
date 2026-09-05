{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Rfc5280.AuthorityInfoAccessSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.Rfc5280.AuthorityInfoAccess'.
-}
module Rfc5280.AuthorityInfoAccessSpec (spec) where

import qualified Data.ByteString as BS
import Data.Rfc5280 (renderConfig)
import Data.Rfc5280.Assert (assertRight)
import Data.Rfc5280.AuthorityInfoAccess
import Data.Rfc5280.GeneralName
import Rfc5280.Generators (validDnsName)
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll)
import Text.URI (mkURI)


spec :: Spec
spec = describe "module Data.Rfc5280.AuthorityInfoAccess" $ do
  context "mkAuthorityInfoAccess" $ do
    it "renders a single OCSP entry" $ do
      uri <- mkURI "http://ocsp.example.com"
      renderConfig (mkAuthorityInfoAccess (OCSP (URIName uri)) [])
        `shouldBe` "OCSP;URI:http://ocsp.example.com"
    it "renders a single CAIssuers entry" $ do
      uri <- mkURI "http://ca.example.com/issuer.crt"
      renderConfig (mkAuthorityInfoAccess (CAIssuers (URIName uri)) [])
        `shouldBe` "caIssuers;URI:http://ca.example.com/issuer.crt"
    it "renders OCSP and CAIssuers together" $ do
      ocspUri <- mkURI "http://ocsp.example.com"
      issuerUri <- mkURI "http://ca.example.com/issuer.crt"
      renderConfig
        ( mkAuthorityInfoAccess
            (OCSP (URIName ocspUri))
            [CAIssuers (URIName issuerUri)]
        )
        `shouldBe` "OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://ca.example.com/issuer.crt"
    it "renders an Other name as OCSP location" $ do
      gn <- assertRight (mkOther 1 [2, 3] UTF8String "value")
      renderConfig (mkAuthorityInfoAccess (OCSP gn) [])
        `shouldBe` "OCSP;otherName:1.2.3;UTF8:value"
    prop "OCSP entries always start with OCSP;" $
      forAll validDnsName $ \dn ->
        BS.isPrefixOf "OCSP;" (renderConfig (mkAuthorityInfoAccess (OCSP (DNS dn)) []))
    prop "CAIssuers entries always start with caIssuers;" $
      forAll validDnsName $ \dn ->
        BS.isPrefixOf "caIssuers;" (renderConfig (mkAuthorityInfoAccess (CAIssuers (DNS dn)) []))
