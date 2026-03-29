{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.ExtensionSpec
Copyright   : (c) 2023 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3
-}
module X509.ExtensionSpec (spec) where

import Test.Hspec
import DataType.X509.Extension

spec :: Spec
spec = describe "module DataType.X509.Extension" $ do
  context "endsThen" $
    it "should be a simple test" $ do
      getIt `endsThen` (== (Just "a string"))


getIt :: IO (Maybe String)
getIt = pure $ Just "a string"
