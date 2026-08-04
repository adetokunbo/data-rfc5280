{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.NameConstraints
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'NameConstraints', representing the X.509 Name Constraints extension
(RFC 5280 §4.2.1.10).

The @minimum@ and @maximum@ fields of @GeneralSubtree@ are not modelled; they
are almost never used in practice and are not supported in OpenSSL config format.
-}
module DataType.X509.Extension.NameConstraints
  ( NameConstraints (..)
  , mkNameConstraints
  , NameConstraint (..)
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.GeneralName (GeneralName)
import DataType.X509.Extension.HasOID (HasOID (..))
import DataType.X509.Extension.Internal (intersperseCommas)


{- | A single name constraint, either permitting or excluding a subtree
identified by a 'GeneralName'.
-}
data NameConstraint
  = -- | A permitted subtree. Rendered as @permitted;\<name\>@.
    Permitted !GeneralName
  | -- | An excluded subtree. Rendered as @excluded;\<name\>@.
    Excluded !GeneralName
  deriving (Eq, Show)


{- | Represents the NameConstraints extension (RFC 5280 §4.2.1.10).

Contains one or more 'NameConstraint' values. Use 'mkNameConstraints' to
construct a value.
-}
newtype NameConstraints = NameConstraints (NonEmpty NameConstraint)
  deriving (Eq, Show)


-- | Construct a 'NameConstraints' from one or more 'NameConstraint' values.
mkNameConstraints :: NameConstraint -> [NameConstraint] -> NameConstraints
mkNameConstraints x xs = NameConstraints (x :| xs)


instance HasOID NameConstraints where
  extensionOID _ = 2 :| [5, 29, 30]


instance ToBuilder NameConstraint Builder where
  toBuilder (Permitted name) = "permitted;" <> toBuilder name
  toBuilder (Excluded  name) = "excluded;"  <> toBuilder name


instance ToBuilder NameConstraints Builder where
  toBuilder (NameConstraints cs) = intersperseCommas (fmap toBuilder cs)
