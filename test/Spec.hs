{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import qualified X509.Extension.GeneralNameSpec as GeneralName
import qualified X509.Extension.SubjectAltNameSpec as SubjectAltName
import qualified X509.ExtensionSpec as Extension
import System.IO (
  BufferMode (..),
  hSetBuffering,
  stderr,
  stdout,
 )
import Test.Hspec


main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  hSetBuffering stderr NoBuffering
  hspec $ do
    Extension.spec
    GeneralName.spec
    SubjectAltName.spec
