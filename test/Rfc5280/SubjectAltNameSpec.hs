{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Rfc5280.SubjectAltNameSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.Rfc5280.SubjectAltName'.
-}
module Rfc5280.SubjectAltNameSpec (spec) where

import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty (..))
import Data.Rfc5280 (renderConfig)
import Data.Rfc5280.Assert (assertRight)
import Data.Rfc5280.GeneralName
import Data.Rfc5280.SubjectAltName
import Rfc5280.Fixtures (testEmail, testIP)
import Rfc5280.Generators (validDnsName, vectorOf1)
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (choose, forAll, (===))


spec :: Spec
spec = describe "module Data.Rfc5280.SubjectAltName" $ do
  context "mkSubjectAltName" $ do
    it "renders a single DNS name" $ do
      dn <- assertRight (mkDnsName "example.com")
      renderConfig (mkSubjectAltName (DNS dn) [])
        `shouldBe` "DNS:example.com"
    it "renders two DNS names" $ do
      dn1 <- assertRight (mkDnsName "example.com")
      dn2 <- assertRight (mkDnsName "www.example.com")
      renderConfig (mkSubjectAltName (DNS dn1) [DNS dn2])
        `shouldBe` "DNS:example.com,DNS:www.example.com"
    it "renders a wildcard alongside its base domain" $ do
      wild <- assertRight (mkDnsName "*.example.com")
      base <- assertRight (mkDnsName "example.com")
      renderConfig (mkSubjectAltName (DNS wild) [DNS base])
        `shouldBe` "DNS:*.example.com,DNS:example.com"
    it "renders mixed DNS, IP and email names" $ do
      ip <- testIP "192.0.2.1"
      addr <- testEmail "user@example.com"
      dn <- assertRight (mkDnsName "example.com")
      renderConfig
        ( mkSubjectAltName
            (DNS dn)
            [IPAddr ip, EmailAddr addr]
        )
        `shouldBe` "DNS:example.com,IP:192.0.2.1,email:user@example.com"
    it "renders an Other name" $ do
      gn <- assertRight (mkOther 1 [2, 3] UTF8String "value")
      renderConfig (mkSubjectAltName gn [])
        `shouldBe` "otherName:1.2.3;UTF8:value"
    prop "a single-name SAN contains no comma" $
      forAll validDnsName $ \dn ->
        BS.elem 0x2C (renderConfig (mkSubjectAltName (DNS dn) [])) === False
    prop "n DNS names produce exactly n-1 comma separators" $
      forAll (choose (1, 6)) $ \n ->
        forAll (vectorOf1 n validDnsName) $ \(h :| tl) ->
          let bs = renderConfig (mkSubjectAltName (DNS h) (map DNS tl))
           in BS.length (BS.filter (== 0x2C) bs) === n - 1
