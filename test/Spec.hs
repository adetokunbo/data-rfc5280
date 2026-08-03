{- |
Module      : Main
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Test suite entry point for x509-extensions.
-}
module Main where

import qualified X509.Extension.AuthorityInfoAccessSpec as AuthorityInfoAccess
import qualified X509.Extension.CRLDistributionPointsSpec as CRLDistributionPoints
import qualified X509.Extension.GeneralNameSpec as GeneralName
import qualified X509.Extension.HasOIDSpec as HasOID
import qualified X509.Extension.IssuerAltNameSpec as IssuerAltName
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
    AuthorityInfoAccess.spec
    CRLDistributionPoints.spec
    GeneralName.spec
    HasOID.spec
    IssuerAltName.spec
    SubjectAltName.spec
