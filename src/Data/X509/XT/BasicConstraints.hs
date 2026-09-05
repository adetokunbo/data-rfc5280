{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.X509.XT.BasicConstraints
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3


Provides the 'BasicConstraints' extension type and its smart constructor.
-}
module Data.X509.XT.BasicConstraints
  ( BasicConstraints (..)
  , BasicConstraintsError (..)
  , mkBasicConstraints
  )
where

import Data.X509.XT.Internal (RenderConfig (..))
import Data.ByteString.Builder (intDec)
import Data.List.NonEmpty (NonEmpty (..))
import Data.X509.XT.HasOID (HasOID (..))


{- | Represents the basic constraints extension

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9 RFC 5280 §4.2.1.9>.
-}
data BasicConstraints
  = BasicConstraints
  { bcIsCA :: !Bool
  -- ^ is the subject of the certificate a certificate authority
  , bcPathLength :: !(Maybe Int)
  {- ^ the maximum number of non-self-issued intermediate certificates
  that may follow this certificate in the path; only meaningful when
  'bcIsCA' is 'True'
  -}
  }
  deriving (Eq, Show)


-- | Failure modes for 'mkBasicConstraints'.
data BasicConstraintsError
  = -- | @pathLenConstraint@ is present but @cA@ is @FALSE@.
    PathLenWithoutCA
  deriving (Eq, Show)


{- | Construct a 'BasicConstraints', validating that @pathLenConstraint@ is
absent when @cA@ is @FALSE@ (RFC 5280 §4.2.1.9).
-}
mkBasicConstraints :: Bool -> Maybe Int -> Either BasicConstraintsError BasicConstraints
mkBasicConstraints False (Just _) = Left PathLenWithoutCA
mkBasicConstraints isCA pathLen = Right $ BasicConstraints{bcIsCA = isCA, bcPathLength = pathLen}


instance HasOID BasicConstraints where
  extensionOID _ = 2 :| [5, 29, 19]


instance RenderConfig BasicConstraints where
  renderBuilder bc =
    let BasicConstraints{bcIsCA, bcPathLength} = bc
        bcPrefix = "CA:"
        bcSuffix = if bcIsCA then "TRUE" else "FALSE"
        withPathLen x = ",pathLen" <> intDec x
        pathLen = maybe "" withPathLen bcPathLength
     in (bcPrefix <> bcSuffix <> pathLen)
