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
  context "BasicConstraints" $
    it "converts to ByteString" $ do
      asByteString notCA `shouldBe` "CA:FALSE"
  context "KeyUsage" $
    it "converts to ByteString" $ do
      asByteString simpleKeyUsage `shouldBe` "digitalSignature,cRLSign"


notCA :: BasicConstraints
notCA =
  BasicConstraints
    { bcIsCA = False
    , bcPathLength = Nothing
    }


simpleKeyUsage :: KeyUsage
simpleKeyUsage = fromList [DigitalSignature, CRLSign]
