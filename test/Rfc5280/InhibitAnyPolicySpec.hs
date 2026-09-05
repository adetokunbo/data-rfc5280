{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Rfc5280.InhibitAnyPolicySpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.X509.XT.InhibitAnyPolicy'.
-}
module Rfc5280.InhibitAnyPolicySpec (spec) where

import Data.X509.XT (renderConfig)
import Data.X509.XT.InhibitAnyPolicy
import Test.Hspec


spec :: Spec
spec = describe "module Data.X509.XT.InhibitAnyPolicy" $ do
  context "mkInhibitAnyPolicy" $ do
    it "accepts zero" $
      mkInhibitAnyPolicy 0 `shouldBe` Right (InhibitAnyPolicy 0)
    it "accepts a positive value" $
      mkInhibitAnyPolicy 2 `shouldBe` Right (InhibitAnyPolicy 2)
    it "rejects a negative value" $
      mkInhibitAnyPolicy (-1) `shouldBe` Left NegativeSkipCerts
  context "RenderConfig" $ do
    it "renders zero" $
      renderConfig (InhibitAnyPolicy 0) `shouldBe` "0"
    it "renders a positive value" $
      renderConfig (InhibitAnyPolicy 5) `shouldBe` "5"
