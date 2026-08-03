{-# LANGUAGE MultiParamTypeClasses #-}

{- |
Module      : DataType.X509.Extension.CRLDistributionPoints
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'CRLDistributionPoints', representing the X.509 CRL Distribution
Points extension (RFC 5280 §4.2.1.13).

Only simple distribution points are modelled: each point carries a single
full-name 'GeneralName' location. The @reasons@, @cRLIssuer@, and
@nameRelativeToCRLIssuer@ fields from the RFC are not yet supported; those
require section-based OpenSSL config syntax which this library does not produce.
-}
module DataType.X509.Extension.CRLDistributionPoints
  ( CRLDistributionPoints (..)
  , mkCRLDistributionPoints
  , DistributionPoint (..)
  , mkDistributionPoint
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.GeneralName (GeneralName)
import DataType.X509.Extension.HasOID (HasOID (..))
import DataType.X509.Extension.Internal (intersperseCommas)


{- | A single CRL distribution point, identified by its full-name location.

In the OpenSSL config format, each 'DistributionPoint' renders as the
'GeneralName' of its location. In practice the location is almost always
a 'URIName'.
-}
newtype DistributionPoint = DistributionPoint GeneralName
  deriving (Eq, Show)


{- | Represents the CRLDistributionPoints extension (RFC 5280 §4.2.1.13).

Contains one or more 'DistributionPoint' values. Use 'mkCRLDistributionPoints'
to construct a value.
-}
newtype CRLDistributionPoints = CRLDistributionPoints (NonEmpty DistributionPoint)
  deriving (Eq, Show)


-- | Construct a 'DistributionPoint' from a 'GeneralName' full-name location.
mkDistributionPoint :: GeneralName -> DistributionPoint
mkDistributionPoint = DistributionPoint


-- | Construct a 'CRLDistributionPoints' from one or more 'DistributionPoint' values.
mkCRLDistributionPoints :: DistributionPoint -> [DistributionPoint] -> CRLDistributionPoints
mkCRLDistributionPoints x xs = CRLDistributionPoints (x :| xs)


instance HasOID CRLDistributionPoints where
  extensionOID _ = 2 :| [5, 29, 31]


instance ToBuilder DistributionPoint Builder where
  toBuilder (DistributionPoint name) = toBuilder name


instance ToBuilder CRLDistributionPoints Builder where
  toBuilder (CRLDistributionPoints pts) = intersperseCommas (fmap toBuilder pts)
