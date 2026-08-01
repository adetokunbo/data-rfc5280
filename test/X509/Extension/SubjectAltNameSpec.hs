{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.SubjectAltNameSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.SubjectAltName'.
-}
module X509.Extension.SubjectAltNameSpec (spec) where

import DataType.X509.Extension (asByteString)
import DataType.X509.Extension.GeneralName
import DataType.X509.Extension.SubjectAltName
import qualified Net.IP as IP
import Test.Hspec
import Text.Email.Validate (validate)


spec :: Spec
spec = describe "module DataType.X509.Extension.SubjectAltName" $ do
  context "mkSubjectAltName" $ do
    it "renders a single DNS name" $
      asByteString (mkSubjectAltName (DNSName "example.com") [])
        `shouldBe` "DNS:example.com"
    it "renders two DNS names" $
      asByteString (mkSubjectAltName (DNSName "example.com") [DNSName "www.example.com"])
        `shouldBe` "DNS:example.com,DNS:www.example.com"
    it "renders a wildcard alongside its base domain" $
      asByteString (mkSubjectAltName (DNSName "*.example.com") [DNSName "example.com"])
        `shouldBe` "DNS:*.example.com,DNS:example.com"
    it "renders mixed DNS, IP and email names" $
      case IP.decode "192.0.2.1" of
        Nothing -> expectationFailure "could not decode test IP address"
        Just ip ->
          case validate "user@example.com" of
            Left err -> expectationFailure $ "invalid test email: " <> err
            Right addr ->
              asByteString
                ( mkSubjectAltName
                    (DNSName "example.com")
                    [IPAddr ip, EmailAddr addr]
                )
                `shouldBe` "DNS:example.com,IP:192.0.2.1,email:user@example.com"
