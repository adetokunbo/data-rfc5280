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
import DataType.X509.Extension (renderOpenSSLConfig, NonEmpty (..))
import DataType.X509.Extension.GeneralName
import DataType.X509.Extension.SubjectAltName
import qualified Net.IP as IP
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (choose, forAll, vectorOf, (===))
import Text.Email.Validate (validate)
import X509.Extension.Generators (validDNSName)


spec :: Spec
spec = describe "module DataType.X509.Extension.SubjectAltName" $ do
  context "mkSubjectAltName" $ do
    it "renders a single DNS name" $
      renderOpenSSLConfig (mkSubjectAltName (DNS (DnsName "example.com")) [])
        `shouldBe` "DNS:example.com"
    it "renders two DNS names" $
      renderOpenSSLConfig (mkSubjectAltName (DNS (DnsName "example.com")) [DNS (DnsName "www.example.com")])
        `shouldBe` "DNS:example.com,DNS:www.example.com"
    it "renders a wildcard alongside its base domain" $
      renderOpenSSLConfig (mkSubjectAltName (DNS (DnsName "*.example.com")) [DNS (DnsName "example.com")])
        `shouldBe` "DNS:*.example.com,DNS:example.com"
    it "renders mixed DNS, IP and email names" $
      case IP.decode "192.0.2.1" of
        Nothing -> expectationFailure "could not decode test IP address"
        Just ip ->
          case validate "user@example.com" of
            Left err -> expectationFailure $ "invalid test email: " <> err
            Right addr ->
              renderOpenSSLConfig
                ( mkSubjectAltName
                    (DNS (DnsName "example.com"))
                    [IPAddr ip, EmailAddr addr]
                )
                `shouldBe` "DNS:example.com,IP:192.0.2.1,email:user@example.com"
    it "renders an Other name" $
      renderOpenSSLConfig (mkSubjectAltName (Other (OtherName (1 :| [2, 3]) UTF8String "value")) [])
        `shouldBe` "otherName:1.2.3;UTF8:value"
    prop "a single-name SAN contains no comma" $
      forAll validDNSName $ \n ->
        BS.elem 0x2C (renderOpenSSLConfig (mkSubjectAltName (DNS (DnsName n)) [])) === False
    prop "n DNS names produce exactly n-1 comma separators" $
      forAll (choose (1, 6)) $ \n ->
        forAll (vectorOf n validDNSName) $ \ns ->
          case ns of
            []     -> True === True
            (h:tl) ->
              let bs = renderOpenSSLConfig (mkSubjectAltName (DNS (DnsName h)) (map (DNS . DnsName) tl))
              in BS.length (BS.filter (== 0x2C) bs) === n - 1
