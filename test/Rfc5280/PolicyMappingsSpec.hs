{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Rfc5280.PolicyMappingsSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.Rfc5280.PolicyMappings'.
-}
module Rfc5280.PolicyMappingsSpec (spec) where

import Data.Rfc5280 (NonEmpty (..), renderConfig)
import Data.Rfc5280.PolicyMappings
import Test.Hspec


spec :: Spec
spec = describe "module Data.Rfc5280.PolicyMappings" $ do
  context "mkPolicyMappings" $ do
    it "renders a single mapping" $
      renderConfig (mkPolicyMappings (mkPolicyMapping (1 :| [2, 3]) (2 :| [5, 4])) [])
        `shouldBe` "1.2.3:2.5.4"
    it "renders two mappings" $
      renderConfig
        ( mkPolicyMappings
            (mkPolicyMapping (1 :| [2, 3]) (2 :| [5, 4]))
            [mkPolicyMapping (1 :| [2, 4]) (2 :| [5, 5])]
        )
        `shouldBe` "1.2.3:2.5.4,1.2.4:2.5.5"
    it "renders a mapping with multi-arc OIDs" $
      renderConfig
        ( mkPolicyMappings
            (mkPolicyMapping (2 :| [16, 840, 1, 101, 3, 2, 1, 3, 6]) (2 :| [16, 840, 1, 101, 3, 2, 1, 12, 4]))
            []
        )
        `shouldBe` "2.16.840.1.101.3.2.1.3.6:2.16.840.1.101.3.2.1.12.4"
