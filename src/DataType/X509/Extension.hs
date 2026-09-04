{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{- |
Module      : DataType.X509.Extension
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Re-export facade for all standard X.509 certificate extension types, with
rendering to OpenSSL configuration format via 'renderOpenSSLConfig'.

Import this module to access every extension type and the 'renderOpenSSLConfig'
utility in one place, or import individual extension modules directly.

This library is encode-only; no parser or decoder is provided.
-}
module DataType.X509.Extension
  ( -- * Extension types
    BasicConstraints (..)
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
  , GeneralName (..)
  , OtherName (..)
  , Asn1StringType (..)
  , DNSNameError (..)
  , mkDNSName
  , mkOtherName

    -- * Alt-name extensions
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
import DataType.X509.Extension.AuthorityKeyIdentifier
  ( AuthorityKeyIdentifier (..)
  , mkAuthorityKeyIdentifier
  )
import DataType.X509.Extension.BasicConstraints
  ( BasicConstraints (..)
  , mkBasicConstraints
  )
import DataType.X509.Extension.CertificatePolicies
  ( CertificatePolicies (..)
  , mkCertificatePolicies
  )
import DataType.X509.Extension.ExtKeyUsage (ExtKeyUsage, ExtKeyUsagePurpose (..))
import DataType.X509.Extension.GeneralName
  ( Asn1StringType (..)
  , DNSNameError (..)
  , GeneralName (..)
  , OtherName (..)
  , mkDNSName
  , mkOtherName
  )
import DataType.X509.Extension.CRLDistributionPoints
  ( CRLDistributionPoints (..)
  , DistributionPoint (..)
  , mkCRLDistributionPoints
  , mkDistributionPoint
  )
import DataType.X509.Extension.HasOID (Extension (..), HasOID (..))
import DataType.X509.Extension.InhibitAnyPolicy (InhibitAnyPolicy (..), mkInhibitAnyPolicy)
import DataType.X509.Extension.NameConstraints
  ( NameConstraint (..)
  , NameConstraints (..)
  , mkNameConstraints
  )
import DataType.X509.Extension.PolicyMappings
  ( PolicyMapping (..)
  , PolicyMappings (..)
  , mkPolicyMapping
  , mkPolicyMappings
  )
import DataType.X509.Extension.IssuerAltName (IssuerAltName (..), mkIssuerAltName)
import DataType.X509.Extension.Internal (OID, OIDError (..), mkOID)
import DataType.X509.Extension.KeyUsage (KeyUsage, KeyUsageBit (..))
import DataType.X509.Extension.SubjectKeyIdentifier (SubjectKeyIdentifier (..))


-- | Render an extension value as a strict 'ByteString' in OpenSSL configuration format.
renderOpenSSLConfig :: (ToBuilder a Builder) => a -> ByteString
renderOpenSSLConfig = BS.toStrict . toLazyByteString . toBuilder
