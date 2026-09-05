{- |
Module      : Main
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Test suite entry point for data-rfc5280.
-}
module Main where

import qualified Rfc5280.AuthorityInfoAccessSpec as AuthorityInfoAccess
import qualified Rfc5280.CRLDistributionPointsSpec as CRLDistributionPoints
import qualified Rfc5280.GeneralNameSpec as GeneralName
import qualified Rfc5280.HasOIDSpec as HasOID
import qualified Rfc5280.InhibitAnyPolicySpec as InhibitAnyPolicy
import qualified Rfc5280.IssuerAltNameSpec as IssuerAltName
import qualified Rfc5280.NameConstraintsSpec as NameConstraints
import qualified Rfc5280.PolicyMappingsSpec as PolicyMappings
import qualified Rfc5280.SubjectAltNameSpec as SubjectAltName
import qualified Rfc5280Spec as Extension
import System.IO
  ( BufferMode (..)
  , hSetBuffering
  , stderr
  , stdout
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
    InhibitAnyPolicy.spec
    IssuerAltName.spec
    NameConstraints.spec
    PolicyMappings.spec
    SubjectAltName.spec
