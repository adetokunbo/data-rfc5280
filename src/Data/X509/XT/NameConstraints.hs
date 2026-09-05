{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.X509.XT.NameConstraints
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'NameConstraints', representing the X.509 Name Constraints extension
(RFC 5280 §4.2.1.10).

The @minimum@ and @maximum@ fields of @GeneralSubtree@ are not modelled; they
are almost never used in practice and are not supported in OpenSSL config format.
-}
module Data.X509.XT.NameConstraints
  ( NameConstraints (..)
  , mkNameConstraints
  , NameConstraint (..)
  ) where

import Data.List.NonEmpty (NonEmpty (..))
import Data.X509.XT.GeneralName (GeneralName)
import Data.X509.XT.HasOID (HasOID (..))
import Data.X509.XT.Internal (RenderConfig (..), intersperseCommas)


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


instance RenderConfig NameConstraint where
  renderBuilder (Permitted name) = "permitted;" <> renderBuilder name
  renderBuilder (Excluded  name) = "excluded;"  <> renderBuilder name


instance RenderConfig NameConstraints where
  renderBuilder (NameConstraints cs) = intersperseCommas (fmap renderBuilder cs)
