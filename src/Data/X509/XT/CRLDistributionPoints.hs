{- |
Module      : Data.X509.XT.CRLDistributionPoints
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
module Data.X509.XT.CRLDistributionPoints
  ( CRLDistributionPoints (..)
  , mkCRLDistributionPoints
  , DistributionPoint (..)
  , mkDistributionPoint
  ) where

import Data.List.NonEmpty (NonEmpty (..))
import Data.X509.XT.GeneralName (GeneralName)
import Data.X509.XT.HasOID (HasOID (..))
import Data.X509.XT.Internal (RenderConfig (..), intersperseCommas)


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


instance RenderConfig DistributionPoint where
  renderBuilder (DistributionPoint name) = renderBuilder name


instance RenderConfig CRLDistributionPoints where
  renderBuilder (CRLDistributionPoints pts) = intersperseCommas (fmap renderBuilder pts)
