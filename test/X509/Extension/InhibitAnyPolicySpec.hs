{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.Extension.InhibitAnyPolicySpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'DataType.X509.Extension.InhibitAnyPolicy'.
-}
module X509.Extension.InhibitAnyPolicySpec (spec) where

import Data.Either (isLeft)
import DataType.X509.Extension (asByteString)
import DataType.X509.Extension.InhibitAnyPolicy
import Test.Hspec


spec :: Spec
spec = describe "module DataType.X509.Extension.InhibitAnyPolicy" $ do
  context "mkInhibitAnyPolicy" $ do
    it "accepts zero" $
      mkInhibitAnyPolicy 0 `shouldBe` Right (InhibitAnyPolicy 0)
    it "accepts a positive value" $
      mkInhibitAnyPolicy 2 `shouldBe` Right (InhibitAnyPolicy 2)
    it "rejects a negative value" $
      mkInhibitAnyPolicy (-1) `shouldSatisfy` isLeft
  context "ToBuilder" $ do
    it "renders zero" $
      asByteString (InhibitAnyPolicy 0) `shouldBe` "0"
    it "renders a positive value" $
      asByteString (InhibitAnyPolicy 5) `shouldBe` "5"
