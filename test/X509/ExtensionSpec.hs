{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : X509.ExtensionSpec
Copyright   : (c) 2023 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3
-}
module X509.ExtensionSpec (spec) where

import DataType.X509.Extension
import Test.Hspec


spec :: Spec
spec = describe "module DataType.X509.Extension" $ do
  context "BasicContraints:asByteString" $
    it "converts to ByteString" $ do
      asByteString notCA `shouldBe` "CA:FALSE"


notCA :: BasicConstraints
notCA =
  BasicConstraints
    { bcIsCA = False
    , bcPathLength = Nothing
    }
