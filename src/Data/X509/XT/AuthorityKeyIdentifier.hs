{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.X509.XT.AuthorityKeyIdentifier
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'AuthorityKeyIdentifier' extension type and its smart constructor.
-}
module Data.X509.XT.AuthorityKeyIdentifier
  ( AuthorityKeyIdentifier (..)
  , mkAuthorityKeyIdentifier
  )
where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import Data.X509.XT.HasOID (HasOID (..))
import Data.X509.XT.Internal (intersperseCommas)


{- | Represents the AuthorityKeyIdentifier extension

see RFC 5280: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
-}
data AuthorityKeyIdentifier = AuthorityKeyIdentifier
  { akiKeyId :: !Bool
  -- ^ include key ID
  , akiKeyIdAlways :: !Bool
  {- ^ always include the key identifier, even if the issuer certificate
  has no SubjectKeyIdentifier extension
  -}
  , akiIssuer :: !Bool
  -- ^ include issuer name + serial
  , akiIssuerAlways :: !Bool
  -- ^ always include
  }
  deriving (Eq, Show)


{- | Construct an 'AuthorityKeyIdentifier', normalising the @always@ flags:
if @keyIdAlways@ is 'True', @keyId@ is set to 'True'; if @issuerAlways@ is
'True', @issuer@ is set to 'True'.
-}
mkAuthorityKeyIdentifier :: Bool -> Bool -> Bool -> Bool -> AuthorityKeyIdentifier
mkAuthorityKeyIdentifier keyId keyIdAlways issuer issuerAlways =
  AuthorityKeyIdentifier
    { akiKeyId = keyId || keyIdAlways
    , akiKeyIdAlways = keyIdAlways
    , akiIssuer = issuer || issuerAlways
    , akiIssuerAlways = issuerAlways
    }


instance HasOID AuthorityKeyIdentifier where
  extensionOID _ = 2 :| [5, 29, 35]


instance ToBuilder AuthorityKeyIdentifier Builder where
  toBuilder aki =
    let keyId
          | akiKeyIdAlways aki = Just "keyid:always"
          | akiKeyId aki = Just "keyid"
          | otherwise = Nothing
        issuer
          | akiIssuerAlways aki = Just "issuer:always"
          | akiIssuer aki = Just "issuer"
          | otherwise = Nothing
     in case (keyId, issuer) of
          (Nothing, Nothing) -> mempty
          (Nothing, Just x) -> x
          (Just x, Nothing) -> x
          (Just x, Just y) -> intersperseCommas (x :| [y])
