{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{- |
Module      : DataType.X509.Extension
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Re-export facade for all standard X.509 certificate extension types, with
rendering to OpenSSL configuration format via 'asByteString'.

Import this module to access every extension type and the 'asByteString'
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
  , mkOID
  , CertificatePolicies (..)
  , mkCertificatePolicies

    -- * General names
  , GeneralName (..)
  , OtherName (..)
  , Asn1StringType (..)
  , mkDNSName

    -- * Criticality wrapper and OID lookup
  , Extension (..)
  , HasOID (..)

    -- * Print types as @ByteString@
  , asByteString

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
import DataType.X509.Extension.GeneralName (Asn1StringType (..), GeneralName (..), OtherName (..), mkDNSName)
import DataType.X509.Extension.HasOID (Extension (..), HasOID (..))
import DataType.X509.Extension.AuthorityKeyIdentifier
  (AuthorityKeyIdentifier (..), mkAuthorityKeyIdentifier)
import DataType.X509.Extension.BasicConstraints
  (BasicConstraints (..), mkBasicConstraints)
import DataType.X509.Extension.CertificatePolicies
  (CertificatePolicies (..), mkCertificatePolicies)
import DataType.X509.Extension.ExtKeyUsage (ExtKeyUsagePurpose (..), ExtKeyUsage)
import DataType.X509.Extension.Internal (OID, mkOID)
import DataType.X509.Extension.KeyUsage (KeyUsageBit (..), KeyUsage)
import DataType.X509.Extension.SubjectKeyIdentifier (SubjectKeyIdentifier (..))


-- | Render an extension value as a strict 'ByteString' in OpenSSL configuration format.
asByteString :: (ToBuilder a Builder) => a -> ByteString
asByteString = BS.toStrict . toLazyByteString . toBuilder
