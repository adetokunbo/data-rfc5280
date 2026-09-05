{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Rfc5280Spec
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3
-}
module Rfc5280Spec (spec) where

import Data.Rfc5280
import Test.Hspec


spec :: Spec
spec = describe "module Data.Rfc5280" $ do
  context "BasicConstraints" $ do
    it "renders a non-CA certificate" $
      renderConfig notCA `shouldBe` "CA:FALSE"
    it "renders a CA certificate" $
      renderConfig isCA `shouldBe` "CA:TRUE"
    it "renders a CA certificate with path length" $
      renderConfig caWithPathLen `shouldBe` "CA:TRUE,pathLen3"
  context "KeyUsage" $ do
    it "renders multiple bits" $
      renderConfig simpleKeyUsage `shouldBe` "digitalSignature,cRLSign"
    it "renders a single bit without a comma" $
      renderConfig singleKeyUsage `shouldBe` "digitalSignature"
    it "renders all bits in Enum order" $
      renderConfig allKeyUsageBits
        `shouldBe` "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign,encipherOnly,decipherOnly"
  context "ExtKeyUsage" $ do
    it "renders multiple purposes" $
      renderConfig simpleExtKeyUsage `shouldBe` "serverAuth,codeSigning"
    it "renders a single purpose without a comma" $
      renderConfig singleExtKeyUsage `shouldBe` "serverAuth"
    it "renders all purposes in Enum order" $
      renderConfig allExtKeyUsagePurposes
        `shouldBe` "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,OCSPSigning,anyExtendedKeyUsage"
  context "SubjectKeyIdentifier" $ do
    it "renders the hash method" $
      renderConfig HashMethod `shouldBe` "hash"
    it "renders raw bytes" $
      renderConfig (Raw "abc") `shouldBe` "abc"
  context "AuthorityKeyIdentifier" $ do
    it "renders keyid:always" $
      renderConfig simpleAKI `shouldBe` "keyid:always"
    it "renders keyid" $
      renderConfig keyIdOnly `shouldBe` "keyid"
    it "renders issuer" $
      renderConfig issuerOnly `shouldBe` "issuer"
    it "renders issuer:always" $
      renderConfig issuerAlwaysAKI `shouldBe` "issuer:always"
    it "renders keyid:always and issuer:always combined" $
      renderConfig bothAlways `shouldBe` "keyid:always,issuer:always"
    it "renders empty when all flags are disabled" $
      renderConfig allDisabled `shouldBe` ""
  context "CertificatePolicies" $ do
    it "renders a single OID" $
      renderConfig simpleCP `shouldBe` "1.2.3.4"
    it "renders multiple OIDs" $
      renderConfig twoOIDs `shouldBe` "1.2.3.4,2.5.4.3"
  context "mkBasicConstraints" $ do
    it "accepts a non-CA without path length" $
      mkBasicConstraints False Nothing `shouldBe` Right notCA
    it "accepts a CA without path length" $
      mkBasicConstraints True Nothing `shouldBe` Right isCA
    it "accepts a CA with path length" $
      mkBasicConstraints True (Just 3) `shouldBe` Right caWithPathLen
    it "rejects a non-CA with path length" $
      mkBasicConstraints False (Just 0) `shouldBe` Left PathLenWithoutCA
  context "mkAuthorityKeyIdentifier" $
    it "sets keyId when keyIdAlways is True" $
      mkAuthorityKeyIdentifier False True False False
        `shouldBe` AuthorityKeyIdentifier
          { akiKeyId = True, akiKeyIdAlways = True, akiIssuer = False, akiIssuerAlways = False }
  context "mkOID" $ do
    it "accepts a valid OID" $
      mkOID 1 [2, 3, 4] `shouldBe` Right (1 :| [2, 3, 4])
    it "rejects a negative first arc" $
      mkOID (-1) [] `shouldBe` Left InvalidFirstArc
    it "rejects a first arc greater than 2" $
      mkOID 3 [] `shouldBe` Left InvalidFirstArc
    it "rejects a negative subsequent arc" $
      mkOID 1 [-1] `shouldBe` Left NegativeArc


notCA :: BasicConstraints
notCA = BasicConstraints { bcIsCA = False, bcPathLength = Nothing }


isCA :: BasicConstraints
isCA = BasicConstraints { bcIsCA = True, bcPathLength = Nothing }


caWithPathLen :: BasicConstraints
caWithPathLen = BasicConstraints { bcIsCA = True, bcPathLength = Just 3 }


simpleKeyUsage :: KeyUsage
simpleKeyUsage = fromList $ DigitalSignature :| [CRLSign]


singleKeyUsage :: KeyUsage
singleKeyUsage = fromList $ DigitalSignature :| []


allKeyUsageBits :: KeyUsage
allKeyUsageBits = fromList $ DigitalSignature :| [NonRepudiation, KeyEncipherment, DataEncipherment, KeyAgreement, KeyCertSign, CRLSign, EncipherOnly, DecipherOnly]


simpleExtKeyUsage :: ExtKeyUsage
simpleExtKeyUsage = fromList $ ServerAuth :| [CodeSigning]


singleExtKeyUsage :: ExtKeyUsage
singleExtKeyUsage = fromList $ ServerAuth :| []


allExtKeyUsagePurposes :: ExtKeyUsage
allExtKeyUsagePurposes = fromList $ ServerAuth :| [ClientAuth, CodeSigning, EmailProtection, TimeStamping, OCSPSigning, AnyExtendedKeyUsage]


simpleAKI :: AuthorityKeyIdentifier
simpleAKI = AuthorityKeyIdentifier { akiKeyId = True, akiKeyIdAlways = True, akiIssuer = False, akiIssuerAlways = False }


keyIdOnly :: AuthorityKeyIdentifier
keyIdOnly = AuthorityKeyIdentifier { akiKeyId = True, akiKeyIdAlways = False, akiIssuer = False, akiIssuerAlways = False }


issuerOnly :: AuthorityKeyIdentifier
issuerOnly = AuthorityKeyIdentifier { akiKeyId = False, akiKeyIdAlways = False, akiIssuer = True, akiIssuerAlways = False }


issuerAlwaysAKI :: AuthorityKeyIdentifier
issuerAlwaysAKI = AuthorityKeyIdentifier { akiKeyId = False, akiKeyIdAlways = False, akiIssuer = False, akiIssuerAlways = True }


bothAlways :: AuthorityKeyIdentifier
bothAlways = AuthorityKeyIdentifier { akiKeyId = False, akiKeyIdAlways = True, akiIssuer = False, akiIssuerAlways = True }


allDisabled :: AuthorityKeyIdentifier
allDisabled = AuthorityKeyIdentifier { akiKeyId = False, akiKeyIdAlways = False, akiIssuer = False, akiIssuerAlways = False }


simpleCP :: CertificatePolicies
simpleCP = mkCertificatePolicies (1 :| [2, 3, 4]) []


twoOIDs :: CertificatePolicies
twoOIDs = mkCertificatePolicies (1 :| [2, 3, 4]) [2 :| [5, 4, 3]]
