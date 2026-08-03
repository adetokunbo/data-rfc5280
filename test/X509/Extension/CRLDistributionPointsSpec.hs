{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.CRLDistributionPointsSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.CRLDistributionPoints'.
-}
module X509.Extension.CRLDistributionPointsSpec (spec) where

import qualified Data.ByteString as BS
import DataType.X509.Extension (asByteString, NonEmpty (..))
import DataType.X509.Extension.CRLDistributionPoints
import DataType.X509.Extension.GeneralName
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (choose, forAll, vectorOf, (===))
import Text.URI (mkURI)
import X509.Extension.Generators (validDNSName)


spec :: Spec
spec = describe "module DataType.X509.Extension.CRLDistributionPoints" $ do
  context "mkCRLDistributionPoints" $ do
    it "renders a single URI distribution point" $ do
      uri <- mkURI "http://crl.example.com/crl.crl"
      asByteString (mkCRLDistributionPoints (mkDistributionPoint (URIName uri)) [])
        `shouldBe` "URI:http://crl.example.com/crl.crl"
    it "renders two URI distribution points" $ do
      uri1 <- mkURI "http://crl1.example.com/crl.crl"
      uri2 <- mkURI "http://crl2.example.com/crl.crl"
      asByteString
        ( mkCRLDistributionPoints
            (mkDistributionPoint (URIName uri1))
            [mkDistributionPoint (URIName uri2)]
        )
        `shouldBe` "URI:http://crl1.example.com/crl.crl,URI:http://crl2.example.com/crl.crl"
    it "renders a DNS-name distribution point" $
      asByteString (mkCRLDistributionPoints (mkDistributionPoint (DNSName "crl.example.com")) [])
        `shouldBe` "DNS:crl.example.com"
    it "renders an Other distribution point" $
      asByteString
        ( mkCRLDistributionPoints
            (mkDistributionPoint (Other (OtherName (1 :| [2, 3]) UTF8String "value")))
            []
        )
        `shouldBe` "otherName:1.2.3;UTF8:value"
    prop "a single distribution point contains no comma" $
      forAll validDNSName $ \n ->
        BS.elem 0x2C (asByteString (mkCRLDistributionPoints (mkDistributionPoint (DNSName n)) [])) === False
    prop "n distribution points produce exactly n-1 comma separators" $
      forAll (choose (1, 6)) $ \n ->
        forAll (vectorOf n validDNSName) $ \ns ->
          case ns of
            []    -> True === True
            (h:tl) ->
              let pts = mkCRLDistributionPoints
                          (mkDistributionPoint (DNSName h))
                          (map (mkDistributionPoint . DNSName) tl)
                  bs = asByteString pts
              in BS.length (BS.filter (== 0x2C) bs) === n - 1
