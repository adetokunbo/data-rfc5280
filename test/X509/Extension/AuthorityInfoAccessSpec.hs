{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.AuthorityInfoAccessSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.AuthorityInfoAccess'.
-}
module X509.Extension.AuthorityInfoAccessSpec (spec) where

import qualified Data.ByteString as BS
import DataType.X509.Extension (asByteString, NonEmpty (..))
import DataType.X509.Extension.AuthorityInfoAccess
import DataType.X509.Extension.GeneralName
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll)
import Text.URI (mkURI)
import X509.Extension.Generators (validDNSName)


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
    it "renders an Other name as OCSP location" $
      asByteString
        ( mkAuthorityInfoAccess
            (OCSP (Other (OtherName (1 :| [2, 3]) UTF8String "value")))
            []
        )
        `shouldBe` "OCSP;otherName:1.2.3;UTF8:value"
    prop "OCSP entries always start with OCSP;" $
      forAll validDNSName $ \n ->
        BS.isPrefixOf "OCSP;" (asByteString (mkAuthorityInfoAccess (OCSP (DNSName n)) []))
    prop "CAIssuers entries always start with caIssuers;" $
      forAll validDNSName $ \n ->
        BS.isPrefixOf "caIssuers;" (asByteString (mkAuthorityInfoAccess (CAIssuers (DNSName n)) []))
