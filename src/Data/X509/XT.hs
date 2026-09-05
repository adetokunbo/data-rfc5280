{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : Data.X509.XT
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Represent the standard X.509v3 certificate extensions from RFC 5280.
Each section below provides constructors for one or more extension types;
'renderConfig' serialises any of them to OpenSSL configuration format.
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
  , CertificatePolicies (..)
  , mkCertificatePolicies

    -- * OID construction
  , OID
  , OIDError (..)
  , mkOID

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
  , RenderConfig (..)
  , renderConfig

    -- * Re-exported for convenience

    -- | 'NonEmpty' from "Data.List.NonEmpty"; 'fromList' from "Data.Set.NonEmpty".
  , fromList
  , NonEmpty (..)
  )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (toLazyByteString)
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
import Data.X509.XT.CRLDistributionPoints
  ( CRLDistributionPoints (..)
  , DistributionPoint (..)
  , mkCRLDistributionPoints
  , mkDistributionPoint
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
  , GeneralName (DNS, EmailAddr, IPAddr, Other, URIName)
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
import Data.X509.XT.HasOID (Extension (..), HasOID (..))
import Data.X509.XT.InhibitAnyPolicy (InhibitAnyPolicy (..), InhibitAnyPolicyError (..), mkInhibitAnyPolicy)
import Data.X509.XT.Internal (OID, OIDError (..), RenderConfig (..), mkOID)
import Data.X509.XT.IssuerAltName (IssuerAltName (..), mkIssuerAltName)
import Data.X509.XT.KeyUsage (KeyUsage, KeyUsageBit (..))
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
import Data.X509.XT.SubjectAltName (SubjectAltName (..), mkSubjectAltName)
import Data.X509.XT.SubjectKeyIdentifier (SubjectKeyIdentifier (..))


-- | Render an extension value as a strict 'ByteString' in OpenSSL configuration format.
renderConfig :: RenderConfig a => a -> ByteString
renderConfig = BS.toStrict . toLazyByteString . renderBuilder
