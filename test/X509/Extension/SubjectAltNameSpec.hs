{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.SubjectAltNameSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.SubjectAltName'.
-}
module X509.Extension.SubjectAltNameSpec (spec) where

import qualified Data.ByteString as BS
import DataType.X509.Extension (renderOpenSSLConfig)
import DataType.X509.Extension.GeneralName
import DataType.X509.Extension.SubjectAltName
import qualified Net.IP as IP
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (choose, forAll, vectorOf, (===))
import Text.Email.Validate (validate)
import X509.Extension.Generators (validDnsName)


spec :: Spec
spec = describe "module DataType.X509.Extension.SubjectAltName" $ do
  context "mkSubjectAltName" $ do
    it "renders a single DNS name" $ do
      dn <- either (fail . show) pure (mkDnsName "example.com")
      renderOpenSSLConfig (mkSubjectAltName (DNS dn) [])
        `shouldBe` "DNS:example.com"
    it "renders two DNS names" $ do
      dn1 <- either (fail . show) pure (mkDnsName "example.com")
      dn2 <- either (fail . show) pure (mkDnsName "www.example.com")
      renderOpenSSLConfig (mkSubjectAltName (DNS dn1) [DNS dn2])
        `shouldBe` "DNS:example.com,DNS:www.example.com"
    it "renders a wildcard alongside its base domain" $ do
      wild <- either (fail . show) pure (mkDnsName "*.example.com")
      base <- either (fail . show) pure (mkDnsName "example.com")
      renderOpenSSLConfig (mkSubjectAltName (DNS wild) [DNS base])
        `shouldBe` "DNS:*.example.com,DNS:example.com"
    it "renders mixed DNS, IP and email names" $
      case IP.decode "192.0.2.1" of
        Nothing -> expectationFailure "could not decode test IP address"
        Just ip ->
          case validate "user@example.com" of
            Left err -> expectationFailure $ "invalid test email: " <> err
            Right addr -> do
              dn <- either (fail . show) pure (mkDnsName "example.com")
              renderOpenSSLConfig
                ( mkSubjectAltName
                    (DNS dn)
                    [IPAddr ip, EmailAddr addr]
                )
                `shouldBe` "DNS:example.com,IP:192.0.2.1,email:user@example.com"
    it "renders an Other name" $ do
      gn <- either (fail . show) pure (mkOther 1 [2, 3] UTF8String "value")
      renderOpenSSLConfig (mkSubjectAltName gn [])
        `shouldBe` "otherName:1.2.3;UTF8:value"
    prop "a single-name SAN contains no comma" $
      forAll validDnsName $ \dn ->
        BS.elem 0x2C (renderOpenSSLConfig (mkSubjectAltName (DNS dn) [])) === False
    prop "n DNS names produce exactly n-1 comma separators" $
      forAll (choose (1, 6)) $ \n ->
        forAll (vectorOf n validDnsName) $ \dns ->
          case dns of
            []     -> True === True
            (h:tl) ->
              let bs = renderOpenSSLConfig (mkSubjectAltName (DNS h) (map DNS tl))
              in BS.length (BS.filter (== 0x2C) bs) === n - 1
