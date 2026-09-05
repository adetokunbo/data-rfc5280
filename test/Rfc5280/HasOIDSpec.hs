{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Rfc5280.HasOIDSpec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Tests for 'Data.Rfc5280.HasOID'.
-}
module Rfc5280.HasOIDSpec (spec) where

import Data.Proxy (Proxy (..))
import Data.Rfc5280
  ( AuthorityKeyIdentifier
  , BasicConstraints (..)
  , CertificatePolicies
  , ExtKeyUsage
  , KeyUsage
  , NonEmpty (..)
  , SubjectKeyIdentifier
  , renderConfig
  )
import Data.Rfc5280.AuthorityInfoAccess (AuthorityInfoAccess)
import Data.Rfc5280.HasOID (Extension (..), HasOID (..), extensionOID)
import Data.Rfc5280.SubjectAltName (SubjectAltName)
import Test.Hspec


spec :: Spec
spec = describe "module Data.Rfc5280.HasOID" $ do
  context "extensionOID" $ do
    it "returns the OID for BasicConstraints" $
      extensionOID (Proxy :: Proxy BasicConstraints) `shouldBe` (2 :| [5, 29, 19])
    it "returns the OID for KeyUsage" $
      extensionOID (Proxy :: Proxy KeyUsage) `shouldBe` (2 :| [5, 29, 15])
    it "returns the OID for ExtKeyUsage" $
      extensionOID (Proxy :: Proxy ExtKeyUsage) `shouldBe` (2 :| [5, 29, 37])
    it "returns the OID for SubjectKeyIdentifier" $
      extensionOID (Proxy :: Proxy SubjectKeyIdentifier) `shouldBe` (2 :| [5, 29, 14])
    it "returns the OID for AuthorityKeyIdentifier" $
      extensionOID (Proxy :: Proxy AuthorityKeyIdentifier) `shouldBe` (2 :| [5, 29, 35])
    it "returns the OID for CertificatePolicies" $
      extensionOID (Proxy :: Proxy CertificatePolicies) `shouldBe` (2 :| [5, 29, 32])
    it "returns the OID for SubjectAltName" $
      extensionOID (Proxy :: Proxy SubjectAltName) `shouldBe` (2 :| [5, 29, 17])
    it "returns the OID for AuthorityInfoAccess" $
      extensionOID (Proxy :: Proxy AuthorityInfoAccess) `shouldBe` (1 :| [3, 6, 1, 5, 5, 7, 1, 1])
  context "Extension (RenderConfig)" $ do
    it "prepends 'critical,' when extCritical is True" $
      renderConfig (Extension True notCA) `shouldBe` "critical,CA:FALSE"
    it "renders the value unchanged when extCritical is False" $
      renderConfig (Extension False notCA) `shouldBe` "CA:FALSE"


notCA :: BasicConstraints
notCA = BasicConstraints{bcIsCA = False, bcPathLength = Nothing}
