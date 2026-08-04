{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.NameConstraintsSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.NameConstraints'.
-}
module X509.Extension.NameConstraintsSpec (spec) where

import qualified Data.ByteString as BS
import DataType.X509.Extension (renderOpenSSLConfig)
import DataType.X509.Extension.GeneralName
import DataType.X509.Extension.NameConstraints
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll, (===))
import X509.Extension.Generators (validDNSName)


spec :: Spec
spec = describe "module DataType.X509.Extension.NameConstraints" $ do
  context "mkNameConstraints" $ do
    it "renders a single permitted DNS constraint" $
      renderOpenSSLConfig (mkNameConstraints (Permitted (DNSName ".example.com")) [])
        `shouldBe` "permitted;DNS:.example.com"
    it "renders a single excluded DNS constraint" $
      renderOpenSSLConfig (mkNameConstraints (Excluded (DNSName ".example.com")) [])
        `shouldBe` "excluded;DNS:.example.com"
    it "renders a single excluded email constraint" $
      renderOpenSSLConfig (mkNameConstraints (Excluded (DNSName ".example.org")) [])
        `shouldBe` "excluded;DNS:.example.org"
    it "renders permitted and excluded constraints together" $
      renderOpenSSLConfig
        ( mkNameConstraints
            (Permitted (DNSName ".example.com"))
            [Excluded (DNSName ".evil.example.com")]
        )
        `shouldBe` "permitted;DNS:.example.com,excluded;DNS:.evil.example.com"
    it "renders multiple permitted constraints" $
      renderOpenSSLConfig
        ( mkNameConstraints
            (Permitted (DNSName ".example.com"))
            [Permitted (DNSName ".example.org")]
        )
        `shouldBe` "permitted;DNS:.example.com,permitted;DNS:.example.org"
    prop "a permitted constraint output starts with \"permitted;\"" $
      forAll validDNSName $ \n ->
        BS.isPrefixOf "permitted;" (renderOpenSSLConfig (mkNameConstraints (Permitted (DNSName n)) [])) === True
    prop "an excluded constraint output starts with \"excluded;\"" $
      forAll validDNSName $ \n ->
        BS.isPrefixOf "excluded;" (renderOpenSSLConfig (mkNameConstraints (Excluded (DNSName n)) [])) === True
