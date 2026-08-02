{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.IssuerAltNameSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.IssuerAltName'.
-}
module X509.Extension.IssuerAltNameSpec (spec) where

import qualified Data.ByteString as BS
import DataType.X509.Extension (asByteString, NonEmpty (..))
import DataType.X509.Extension.GeneralName
import DataType.X509.Extension.IssuerAltName
import qualified Net.IP as IP
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (choose, forAll, vectorOf, (===))
import Text.Email.Validate (validate)
import X509.Extension.Generators (validDNSName)


spec :: Spec
spec = describe "module DataType.X509.Extension.IssuerAltName" $ do
  context "mkIssuerAltName" $ do
    it "renders a single DNS name" $
      asByteString (mkIssuerAltName (DNSName "example.com") [])
        `shouldBe` "DNS:example.com"
    it "renders two DNS names" $
      asByteString (mkIssuerAltName (DNSName "example.com") [DNSName "www.example.com"])
        `shouldBe` "DNS:example.com,DNS:www.example.com"
    it "renders a wildcard alongside its base domain" $
      asByteString (mkIssuerAltName (DNSName "*.example.com") [DNSName "example.com"])
        `shouldBe` "DNS:*.example.com,DNS:example.com"
    it "renders mixed DNS, IP and email names" $
      case IP.decode "192.0.2.1" of
        Nothing -> expectationFailure "could not decode test IP address"
        Just ip ->
          case validate "user@example.com" of
            Left err -> expectationFailure $ "invalid test email: " <> err
            Right addr ->
              asByteString
                ( mkIssuerAltName
                    (DNSName "example.com")
                    [IPAddr ip, EmailAddr addr]
                )
                `shouldBe` "DNS:example.com,IP:192.0.2.1,email:user@example.com"
    it "renders an Other name" $
      asByteString (mkIssuerAltName (Other (OtherName (1 :| [2, 3]) UTF8String "value")) [])
        `shouldBe` "otherName:1.2.3;UTF8:value"
    prop "a single-name IAN contains no comma" $
      forAll validDNSName $ \n ->
        BS.elem 0x2C (asByteString (mkIssuerAltName (DNSName n) [])) === False
    prop "n DNS names produce exactly n-1 comma separators" $
      forAll (choose (1, 6)) $ \n ->
        forAll (vectorOf n validDNSName) $ \ns ->
          case ns of
            []    -> True === True
            (h:tl) ->
              let bs = asByteString (mkIssuerAltName (DNSName h) (map DNSName tl))
              in BS.length (BS.filter (== 0x2C) bs) === n - 1
