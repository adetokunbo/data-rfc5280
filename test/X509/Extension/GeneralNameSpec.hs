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
import DataType.X509.Extension (asByteString, mkOID)
import DataType.X509.Extension.GeneralName
import qualified Net.IP as IP
import Test.Hspec
import Text.Email.Validate (validate)
import Text.URI (mkURI)


spec :: Spec
spec = describe "module DataType.X509.Extension.GeneralName" $ do
  context "DNSName" $
    it "converts to ByteString" $
      asByteString (DNSName "example.com") `shouldBe` "DNS:example.com"
  context "IPAddr (IPv4)" $
    it "converts to ByteString" $
      case IP.decode "192.0.2.1" of
        Nothing -> expectationFailure "could not decode test IPv4 address"
        Just ip -> asByteString (IPAddr ip) `shouldBe` "IP:192.0.2.1"
  context "IPAddr (IPv6)" $
    it "converts to ByteString" $
      case IP.decode "::1" of
        Nothing -> expectationFailure "could not decode test IPv6 address"
        Just ip -> asByteString (IPAddr ip) `shouldBe` "IP:::1"
  context "EmailAddr" $
    it "converts to ByteString" $
      case validate "user@example.com" of
        Left err -> expectationFailure $ "invalid test email: " <> err
        Right addr -> asByteString (EmailAddr addr) `shouldBe` "email:user@example.com"
  context "URIName" $
    it "converts to ByteString" $ do
      uri <- mkURI "https://example.com"
      asByteString (URIName uri) `shouldBe` "URI:https://example.com"
  context "RegisteredID" $
    it "converts to ByteString" $
      asByteString (RegisteredID (mkOID 2 [5, 4, 3])) `shouldBe` "RID:2.5.4.3"
  context "mkDNSName" $ do
    it "accepts a simple hostname" $
      mkDNSName "example.com" `shouldBe` Right (DNSName "example.com")
    it "accepts a multi-label hostname" $
      mkDNSName "foo.bar.example.com" `shouldBe` Right (DNSName "foo.bar.example.com")
    it "accepts a wildcard first label" $
      mkDNSName "*.example.com" `shouldBe` Right (DNSName "*.example.com")
    it "accepts a single label" $
      mkDNSName "localhost" `shouldBe` Right (DNSName "localhost")
    it "rejects an empty name" $
      mkDNSName "" `shouldSatisfy` isLeft
    it "rejects a label ending with a hyphen" $
      mkDNSName "example-.com" `shouldSatisfy` isLeft
    it "rejects a label starting with a hyphen" $
      mkDNSName "-example.com" `shouldSatisfy` isLeft
    it "rejects an empty label" $
      mkDNSName "example..com" `shouldSatisfy` isLeft
    it "rejects a label exceeding 63 characters" $
      mkDNSName (T.replicate 64 "a" <> ".com") `shouldSatisfy` isLeft
    it "rejects a name exceeding 253 characters" $
      mkDNSName (T.intercalate "." (replicate 5 (T.replicate 50 "a"))) `shouldSatisfy` isLeft
