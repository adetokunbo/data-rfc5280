{-# LANGUAGE MultiParamTypeClasses #-}

{- |
Module      : DataType.X509.Extension.InhibitAnyPolicy
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'InhibitAnyPolicy', representing the X.509 Inhibit anyPolicy
extension (RFC 5280 §4.2.1.14).
-}
module DataType.X509.Extension.InhibitAnyPolicy
  ( InhibitAnyPolicy (..)
  , InhibitAnyPolicyError (..)
  , mkInhibitAnyPolicy
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder, intDec)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.HasOID (HasOID (..))


{- | Represents the InhibitAnyPolicy extension (RFC 5280 §4.2.1.14).

The value is the @SkipCerts@ integer, indicating how many additional
certificates may appear in the path before anyPolicy is no longer
acceptable. Use 'mkInhibitAnyPolicy' to construct a value.
-}
newtype InhibitAnyPolicy = InhibitAnyPolicy Int
  deriving (Eq, Show)


-- | Failure modes for 'mkInhibitAnyPolicy'.
data InhibitAnyPolicyError
  = NegativeSkipCerts -- ^ The skip-certs value is negative.
  deriving (Eq, Show)


{- | Construct an 'InhibitAnyPolicy', validating that the skip-certs value
is non-negative.
-}
mkInhibitAnyPolicy :: Int -> Either InhibitAnyPolicyError InhibitAnyPolicy
mkInhibitAnyPolicy n
  | n < 0    = Left NegativeSkipCerts
  | otherwise = Right (InhibitAnyPolicy n)


instance HasOID InhibitAnyPolicy where
  extensionOID _ = 2 :| [5, 29, 54]


instance ToBuilder InhibitAnyPolicy Builder where
  toBuilder (InhibitAnyPolicy n) = intDec n
