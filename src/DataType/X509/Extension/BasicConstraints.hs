{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.BasicConstraints
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'BasicConstraints' extension type and its smart constructor.
-}
module DataType.X509.Extension.BasicConstraints
  ( BasicConstraints (..)
  , BasicConstraintsError (..)
  , mkBasicConstraints
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder, intDec)
import Data.List.NonEmpty (NonEmpty (..))
import DataType.X509.Extension.HasOID (HasOID (..))


{- | Represents the basic constraints extension

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
-}
data BasicConstraints
  = BasicConstraints
  { bcIsCA :: !Bool
  -- ^ is the subject of the certificate a certificate authority
  , bcPathLength :: !(Maybe Int)
  -- ^ the maximum number of non-self-issued intermediate certificates
  -- ^ that may follow this certificate if it is a CA certificate
  }
  deriving (Eq, Show)


-- | Failure modes for 'mkBasicConstraints'.
data BasicConstraintsError
  = PathLenWithoutCA -- ^ @pathLenConstraint@ is present but @cA@ is @FALSE@.
  deriving (Eq, Show)


{- | Construct a 'BasicConstraints', validating that @pathLenConstraint@ is
absent when @cA@ is @FALSE@ (RFC 5280 §4.2.1.9).
-}
mkBasicConstraints :: Bool -> Maybe Int -> Either BasicConstraintsError BasicConstraints
mkBasicConstraints False (Just _) = Left PathLenWithoutCA
mkBasicConstraints isCA pathLen   = Right $ BasicConstraints { bcIsCA = isCA, bcPathLength = pathLen }


instance HasOID BasicConstraints where
  extensionOID _ = 2 :| [5, 29, 19]


instance ToBuilder BasicConstraints Builder where
  toBuilder bc =
    let BasicConstraints{bcIsCA, bcPathLength} = bc
        bcPrefix = "CA:"
        bcSuffix = if bcIsCA then "TRUE" else "FALSE"
        withPathLen x = ",pathLen" <> intDec x
        pathLen = maybe "" withPathLen bcPathLength
     in (bcPrefix <> bcSuffix <> pathLen)
