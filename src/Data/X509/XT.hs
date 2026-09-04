{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : Data.X509.XT
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Re-export facade for all standard X.509 certificate extension types, with
rendering to OpenSSL configuration format via 'renderOpenSSLConfig'.

Import this module to access every extension type and the 'renderOpenSSLConfig'
utility in one place, or import individual extension modules directly.

This library is encode-only; no parser or decoder is provided.
-}
module Data.X509.XT
  ( -- * Extension types
    BasicConstraints (..)
  , BasicConstraintsError (..)
  , mkBasicConstraints
  , KeyUsageBit (..)
  , KeyUsage
  , ExtKeyUsagePurpose (..)
  , ExtKeyUsage
  , SubjectKeyIdentifier (..)
  , AuthorityKeyIdentifier (..)
  , mkAuthorityKeyIdentifier
  , OID
  , OIDError (..)
  , mkOID
  , CertificatePolicies (..)
  , mkCertificatePolicies

    -- * General names
  , GeneralName (DNS, IPAddr, EmailAddr, URIName, Other)
  , pattern RegisteredID
  , DnsName
  , dnsNameText
  , OtherName
  , pattern OtherName
  , onTypeId
  , onEncoding
  , onValue
  , Asn1StringType (..)
  , DNSNameError (..)
  , OtherNameError (..)
  , mkDnsName
  , mkDnsConstraint
  , mkRegisteredID
  , mkOtherName
  , mkOther

    -- * Alt-name extensions
  , SubjectAltName (..)
  , mkSubjectAltName
  , IssuerAltName (..)
  , mkIssuerAltName

    -- * CRL extensions
  , CRLDistributionPoints (..)
  , mkCRLDistributionPoints
  , DistributionPoint (..)
  , mkDistributionPoint

    -- * Name constraints
  , NameConstraints (..)
  , mkNameConstraints
  , NameConstraint (..)

    -- * Policy extensions
  , InhibitAnyPolicy (..)
  , InhibitAnyPolicyError (..)
  , mkInhibitAnyPolicy
  , PolicyMappings (..)
  , mkPolicyMappings
  , PolicyMapping (..)
  , mkPolicyMapping

    -- * Criticality wrapper and OID lookup
  , Extension (..)
  , HasOID (..)

    -- * Render to OpenSSL config format
  , renderOpenSSLConfig

    -- * re-export
  , fromList
  , NonEmpty (..)
  )
where

import Data.Builder (ToBuilder (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder, toLazyByteString)
import Data.List.NonEmpty (NonEmpty (..))
import Data.Set.NonEmpty (fromList)
import Data.X509.XT.AuthorityKeyIdentifier
  ( AuthorityKeyIdentifier (..)
  , mkAuthorityKeyIdentifier
  )
import Data.X509.XT.BasicConstraints
  ( BasicConstraints (..)
  , BasicConstraintsError (..)
  , mkBasicConstraints
  )
import Data.X509.XT.CertificatePolicies
  ( CertificatePolicies (..)
  , mkCertificatePolicies
  )
import Data.X509.XT.ExtKeyUsage (ExtKeyUsage, ExtKeyUsagePurpose (..))
import Data.X509.XT.GeneralName
  ( Asn1StringType (..)
  , DNSNameError (..)
  , DnsName
  , GeneralName (DNS, IPAddr, EmailAddr, URIName, Other)
  , OtherName
  , OtherNameError (..)
  , dnsNameText
  , mkDnsConstraint
  , mkDnsName
  , mkOther
  , mkOtherName
  , mkRegisteredID
  , onEncoding
  , onTypeId
  , onValue
  , pattern OtherName
  , pattern RegisteredID
  )
import Data.X509.XT.CRLDistributionPoints
  ( CRLDistributionPoints (..)
  , DistributionPoint (..)
  , mkCRLDistributionPoints
  , mkDistributionPoint
  )
import Data.X509.XT.HasOID (Extension (..), HasOID (..))
import Data.X509.XT.InhibitAnyPolicy (InhibitAnyPolicy (..), InhibitAnyPolicyError (..), mkInhibitAnyPolicy)
import Data.X509.XT.NameConstraints
  ( NameConstraint (..)
  , NameConstraints (..)
  , mkNameConstraints
  )
import Data.X509.XT.PolicyMappings
  ( PolicyMapping (..)
  , PolicyMappings (..)
  , mkPolicyMapping
  , mkPolicyMappings
  )
import Data.X509.XT.IssuerAltName (IssuerAltName (..), mkIssuerAltName)
import Data.X509.XT.SubjectAltName (SubjectAltName (..), mkSubjectAltName)
import Data.X509.XT.Internal (OID, OIDError (..), mkOID)
import Data.X509.XT.KeyUsage (KeyUsage, KeyUsageBit (..))
import Data.X509.XT.SubjectKeyIdentifier (SubjectKeyIdentifier (..))


-- | Render an extension value as a strict 'ByteString' in OpenSSL configuration format.
renderOpenSSLConfig :: (ToBuilder a Builder) => a -> ByteString
renderOpenSSLConfig = BS.toStrict . toLazyByteString . toBuilder
