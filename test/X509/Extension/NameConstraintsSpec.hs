{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.NameConstraintsSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.X509.XT.NameConstraints'.
-}
module X509.Extension.NameConstraintsSpec (spec) where

import qualified Data.ByteString as BS
import Data.X509.XT (renderConfig)
import Data.X509.XT.GeneralName
import Data.X509.XT.NameConstraints
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll, (===))
import X509.Extension.Fixtures (assertRight)
import X509.Extension.Generators (validDnsName)


spec :: Spec
spec = describe "module Data.X509.XT.NameConstraints" $ do
  context "mkNameConstraints" $ do
    it "renders a single permitted DNS constraint" $ do
      dn <- assertRight (mkDnsConstraint ".example.com")
      renderConfig (mkNameConstraints (Permitted (DNS dn)) [])
        `shouldBe` "permitted;DNS:.example.com"
    it "renders a single excluded DNS constraint" $ do
      dn <- assertRight (mkDnsConstraint ".example.com")
      renderConfig (mkNameConstraints (Excluded (DNS dn)) [])
        `shouldBe` "excluded;DNS:.example.com"
    it "renders a single excluded email constraint" $ do
      dn <- assertRight (mkDnsConstraint ".example.org")
      renderConfig (mkNameConstraints (Excluded (DNS dn)) [])
        `shouldBe` "excluded;DNS:.example.org"
    it "renders permitted and excluded constraints together" $ do
      permitted <- assertRight (mkDnsConstraint ".example.com")
      excluded  <- assertRight (mkDnsConstraint ".evil.example.com")
      renderConfig
        ( mkNameConstraints
            (Permitted (DNS permitted))
            [Excluded (DNS excluded)]
        )
        `shouldBe` "permitted;DNS:.example.com,excluded;DNS:.evil.example.com"
    it "renders multiple permitted constraints" $ do
      dn1 <- assertRight (mkDnsConstraint ".example.com")
      dn2 <- assertRight (mkDnsConstraint ".example.org")
      renderConfig
        ( mkNameConstraints
            (Permitted (DNS dn1))
            [Permitted (DNS dn2)]
        )
        `shouldBe` "permitted;DNS:.example.com,permitted;DNS:.example.org"
    prop "a permitted constraint output starts with \"permitted;\"" $
      forAll validDnsName $ \dn ->
        BS.isPrefixOf "permitted;" (renderConfig (mkNameConstraints (Permitted (DNS dn)) [])) === True
    prop "an excluded constraint output starts with \"excluded;\"" $
      forAll validDnsName $ \dn ->
        BS.isPrefixOf "excluded;" (renderConfig (mkNameConstraints (Excluded (DNS dn)) [])) === True
