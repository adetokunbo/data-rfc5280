{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.PolicyMappingsSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.PolicyMappings'.
-}
module X509.Extension.PolicyMappingsSpec (spec) where

import DataType.X509.Extension (asByteString, NonEmpty (..))
import DataType.X509.Extension.PolicyMappings
import Test.Hspec


spec :: Spec
spec = describe "module DataType.X509.Extension.PolicyMappings" $ do
  context "mkPolicyMappings" $ do
    it "renders a single mapping" $
      asByteString (mkPolicyMappings (mkPolicyMapping (1 :| [2, 3]) (2 :| [5, 4])) [])
        `shouldBe` "1.2.3:2.5.4"
    it "renders two mappings" $
      asByteString
        ( mkPolicyMappings
            (mkPolicyMapping (1 :| [2, 3]) (2 :| [5, 4]))
            [mkPolicyMapping (1 :| [2, 4]) (2 :| [5, 5])]
        )
        `shouldBe` "1.2.3:2.5.4,1.2.4:2.5.5"
    it "renders a mapping with multi-arc OIDs" $
      asByteString
        ( mkPolicyMappings
            (mkPolicyMapping (2 :| [16, 840, 1, 101, 3, 2, 1, 3, 6]) (2 :| [16, 840, 1, 101, 3, 2, 1, 12, 4]))
            []
        )
        `shouldBe` "2.16.840.1.101.3.2.1.3.6:2.16.840.1.101.3.2.1.12.4"
