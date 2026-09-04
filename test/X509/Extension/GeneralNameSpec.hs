{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.GeneralNameSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.GeneralName'.
-}
module X509.Extension.GeneralNameSpec (spec) where

import Data.Either (isLeft)
import qualified Data.Text as T
import DataType.X509.Extension (renderOpenSSLConfig, NonEmpty (..))
import DataType.X509.Extension.GeneralName
import qualified Net.IP as IP
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll, (===))
import X509.Extension.Generators (nameWithInvalidChar, validDNSName)
import Text.Email.Validate (validate)
import Text.URI (mkURI)


spec :: Spec
spec = describe "module DataType.X509.Extension.GeneralName" $ do
  context "DNS" $
    it "converts to ByteString" $
      renderOpenSSLConfig (DNS (DnsName "example.com")) `shouldBe` "DNS:example.com"
  context "IPAddr (IPv4)" $
    it "converts to ByteString" $
      case IP.decode "192.0.2.1" of
        Nothing -> expectationFailure "could not decode test IPv4 address"
        Just ip -> renderOpenSSLConfig (IPAddr ip) `shouldBe` "IP:192.0.2.1"
  context "IPAddr (IPv6)" $
    it "converts to ByteString" $
      case IP.decode "::1" of
        Nothing -> expectationFailure "could not decode test IPv6 address"
        Just ip -> renderOpenSSLConfig (IPAddr ip) `shouldBe` "IP:::1"
  context "EmailAddr" $
    it "converts to ByteString" $
      case validate "user@example.com" of
        Left err -> expectationFailure $ "invalid test email: " <> err
        Right addr -> renderOpenSSLConfig (EmailAddr addr) `shouldBe` "email:user@example.com"
  context "URIName" $
    it "converts to ByteString" $ do
      uri <- mkURI "https://example.com"
      renderOpenSSLConfig (URIName uri) `shouldBe` "URI:https://example.com"
  context "RegisteredID" $
    it "converts to ByteString" $
      renderOpenSSLConfig (RegisteredID (2 :| [5, 4, 3])) `shouldBe` "RID:2.5.4.3"
  context "Other (UTF8String)" $
    it "converts to ByteString" $
      renderOpenSSLConfig (Other (OtherName (1 :| [2, 3]) UTF8String "hello"))
        `shouldBe` "otherName:1.2.3;UTF8:hello"
  context "Other (IA5String)" $
    it "converts to ByteString" $
      renderOpenSSLConfig (Other (OtherName (1 :| [2, 3]) IA5String "hello"))
        `shouldBe` "otherName:1.2.3;IA5:hello"
  context "Other (PrintableString)" $
    it "converts to ByteString" $
      renderOpenSSLConfig (Other (OtherName (1 :| [2, 3]) PrintableString "Hello World"))
        `shouldBe` "otherName:1.2.3;PRINTABLE:Hello World"
  context "Other (BMPString)" $
    it "converts to ByteString" $
      renderOpenSSLConfig (Other (OtherName (1 :| [2, 3]) BMPString "hello"))
        `shouldBe` "otherName:1.2.3;BMP:hello"
  context "mkDnsName" $ do
    it "accepts a simple hostname" $
      mkDnsName "example.com" `shouldBe` Right (DnsName "example.com")
    it "accepts a multi-label hostname" $
      mkDnsName "foo.bar.example.com" `shouldBe` Right (DnsName "foo.bar.example.com")
    it "accepts a wildcard first label" $
      mkDnsName "*.example.com" `shouldBe` Right (DnsName "*.example.com")
    it "accepts a single label" $
      mkDnsName "localhost" `shouldBe` Right (DnsName "localhost")
    it "rejects an empty name" $
      mkDnsName "" `shouldBe` Left NameEmpty
    it "rejects a label ending with a hyphen" $
      mkDnsName "example-.com" `shouldBe` Left LabelTrailingHyphen
    it "rejects a label starting with a hyphen" $
      mkDnsName "-example.com" `shouldBe` Left LabelLeadingHyphen
    it "rejects an empty label" $
      mkDnsName "example..com" `shouldBe` Left NameEmpty
    it "rejects a label exceeding 63 characters" $
      mkDnsName (T.replicate 64 "a" <> ".com") `shouldBe` Left LabelTooLong
    it "rejects a name exceeding 253 characters" $
      mkDnsName (T.intercalate "." (replicate 5 (T.replicate 50 "a"))) `shouldBe` Left NameTooLong
    prop "accepts any validly-constructed hostname" $
      forAll validDNSName $ \t -> mkDnsName t === Right (DnsName t)
    prop "rejects any name containing an invalid label character" $
      forAll nameWithInvalidChar $ \t -> isLeft (mkDnsName t)
  context "mkOtherName" $ do
    it "accepts a valid OID and UTF8String value" $
      mkOtherName 1 [2, 3] UTF8String "hello"
        `shouldBe` Right (OtherName (1 :| [2, 3]) UTF8String "hello")
    it "rejects a negative OID arc" $
      mkOtherName (-1) [2, 3] UTF8String "hello" `shouldBe` Left InvalidOID
    it "rejects IA5String value containing a non-ASCII character" $
      mkOtherName 1 [2, 3] IA5String "h\xe9llo" `shouldBe` Left IA5NonAscii
    it "rejects PrintableString value containing a character outside the alphabet" $
      mkOtherName 1 [2, 3] PrintableString "user@example" `shouldBe` Left PrintableInvalidChar
    it "rejects BMPString value containing a non-BMP character" $
      mkOtherName 1 [2, 3] BMPString "\x1F600" `shouldBe` Left BMPNonBMP


