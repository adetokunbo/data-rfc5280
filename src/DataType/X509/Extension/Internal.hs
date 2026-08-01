{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.Internal
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Internal helpers shared across X.509 extension modules. Not part of the
public API stability guarantee.
-}
module DataType.X509.Extension.Internal
  ( -- * OID
    OID
  , mkOID
  , oidBuilder

    -- * Builder helpers
  , intersperseCommas
  , intersperseWith
  ) where

import Data.ByteString.Builder (Builder, intDec)
import Data.Foldable (foldl')
import Data.List.NonEmpty (NonEmpty (..))


-- | An ASN.1 object identifier.
type OID = NonEmpty Int


-- | Construct an 'OID' from a first arc and remaining arcs.
mkOID :: Int -> [Int] -> OID
mkOID = (:|)


-- | Render an 'OID' as a dot-separated sequence of integers.
oidBuilder :: OID -> Builder
oidBuilder = intersperseWith "." . fmap intDec


-- | Render a non-empty list of 'Builder' values separated by commas.
intersperseCommas :: NonEmpty Builder -> Builder
intersperseCommas = intersperseWith ","


-- | Render a non-empty list of 'Builder' values separated by @sep@.
intersperseWith :: Builder -> NonEmpty Builder -> Builder
intersperseWith sep (x :| xs) = x <> foldl' (\acc y -> acc <> sep <> y) "" xs
