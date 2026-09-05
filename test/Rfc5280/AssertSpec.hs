{- |
Module      : Rfc5280.AssertSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.Rfc5280.Assert'.
-}
module Rfc5280.AssertSpec (spec) where

import Data.Rfc5280.Assert (assertJust, assertRight)
import Test.Hspec


spec :: Spec
spec = do
  describe "assertRight" $ do
    it "returns the value on Right" $ do
      result <- assertRight (Right 42 :: Either String Int)
      result `shouldBe` 42
    it "fails on Left" $
      assertRight (Left "oops" :: Either String Int)
        `shouldThrow` anyException
  describe "assertJust" $ do
    it "returns the value on Just" $ do
      result <- assertJust "missing" (Just 42)
      result `shouldBe` (42 :: Int)
    it "fails with the given message on Nothing" $
      assertJust "missing" (Nothing :: Maybe Int)
        `shouldThrow` anyException
