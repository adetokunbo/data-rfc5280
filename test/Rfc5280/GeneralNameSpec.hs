{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Rfc5280.GeneralNameSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.Rfc5280.GeneralName'.
-}
module Rfc5280.GeneralNameSpec (spec) where

import Data.Either (isLeft)
import qualified Data.Text as T
import Data.Rfc5280 (renderConfig, NonEmpty (..))
import Data.Rfc5280.GeneralName
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll, (===))
import Text.URI (mkURI)
import Rfc5280.Fixtures (assertRight, testEmail, testIP)
import Rfc5280.Generators (nameWithInvalidChar, validDNSName)


spec :: Spec
spec = describe "module Data.Rfc5280.GeneralName" $ do
  context "DNS" $
    it "converts to ByteString" $ do
      dn <- assertRight (mkDnsName "example.com")
      renderConfig (DNS dn) `shouldBe` "DNS:example.com"
  context "IPAddr (IPv4)" $
    it "converts to ByteString" $ do
      ip <- testIP "192.0.2.1"
      renderConfig (IPAddr ip) `shouldBe` "IP:192.0.2.1"
  context "IPAddr (IPv6)" $
    it "converts to ByteString" $ do
      ip <- testIP "::1"
      renderConfig (IPAddr ip) `shouldBe` "IP:::1"
  context "EmailAddr" $
    it "converts to ByteString" $ do
      addr <- testEmail "user@example.com"
      renderConfig (EmailAddr addr) `shouldBe` "email:user@example.com"
  context "URIName" $
    it "converts to ByteString" $ do
      uri <- mkURI "https://example.com"
      renderConfig (URIName uri) `shouldBe` "URI:https://example.com"
  context "RegisteredID" $
    it "converts to ByteString" $ do
      rid <- assertRight (mkRegisteredID 2 [5, 4, 3])
      renderConfig rid `shouldBe` "RID:2.5.4.3"
  context "Other (UTF8String)" $
    it "converts to ByteString" $ do
      gn <- assertRight (mkOther 1 [2, 3] UTF8String "hello")
      renderConfig gn `shouldBe` "otherName:1.2.3;UTF8:hello"
  context "Other (IA5String)" $
    it "converts to ByteString" $ do
      gn <- assertRight (mkOther 1 [2, 3] IA5String "hello")
      renderConfig gn `shouldBe` "otherName:1.2.3;IA5:hello"
  context "Other (PrintableString)" $
    it "converts to ByteString" $ do
      gn <- assertRight (mkOther 1 [2, 3] PrintableString "Hello World")
      renderConfig gn `shouldBe` "otherName:1.2.3;PRINTABLE:Hello World"
  context "Other (BMPString)" $
    it "converts to ByteString" $ do
      gn <- assertRight (mkOther 1 [2, 3] BMPString "hello")
      renderConfig gn `shouldBe` "otherName:1.2.3;BMP:hello"
  context "mkDnsName" $ do
    it "accepts a simple hostname" $
      fmap dnsNameText (mkDnsName "example.com") `shouldBe` Right "example.com"
    it "accepts a multi-label hostname" $
      fmap dnsNameText (mkDnsName "foo.bar.example.com") `shouldBe` Right "foo.bar.example.com"
    it "accepts a wildcard first label" $
      fmap dnsNameText (mkDnsName "*.example.com") `shouldBe` Right "*.example.com"
    it "accepts a single label" $
      fmap dnsNameText (mkDnsName "localhost") `shouldBe` Right "localhost"
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
      forAll validDNSName $ \t -> fmap dnsNameText (mkDnsName t) === Right t
    prop "rejects any name containing an invalid label character" $
      forAll nameWithInvalidChar $ \t -> isLeft (mkDnsName t)
  context "mkOtherName" $ do
    it "accepts a valid OID and UTF8String value" $ do
      on <- assertRight (mkOtherName 1 [2, 3] UTF8String "hello")
      onTypeId on `shouldBe` (1 :| [2, 3])
      onEncoding on `shouldBe` UTF8String
      onValue on `shouldBe` "hello"
    it "rejects a negative OID arc" $
      mkOtherName (-1) [2, 3] UTF8String "hello" `shouldBe` Left InvalidOID
    it "rejects IA5String value containing a non-ASCII character" $
      mkOtherName 1 [2, 3] IA5String "h\xe9llo" `shouldBe` Left IA5NonAscii
    it "rejects PrintableString value containing a character outside the alphabet" $
      mkOtherName 1 [2, 3] PrintableString "user@example" `shouldBe` Left PrintableInvalidChar
    it "rejects BMPString value containing a non-BMP character" $
      mkOtherName 1 [2, 3] BMPString "\x1F600" `shouldBe` Left BMPNonBMP
