{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeSynonymInstances #-}

{- |
Module      : Data.X509.XT.KeyUsage
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'KeyUsage' extension type.
-}
module Data.X509.XT.KeyUsage
  ( KeyUsageBit (..)
  , KeyUsage
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Set.NonEmpty as NES
import Data.X509.XT.HasOID (HasOID (..))
import Data.X509.XT.Internal (intersperseCommas)


{- | Represents the bits that can set for @KeyUsage@

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 RFC 5280 §4.2.1.3>.
-}
data KeyUsageBit
  = -- | Verifying digital signatures other than signatures on certificates or
    -- CRLs. Renders as @\"digitalSignature\"@.
    DigitalSignature
  | -- | Verifying digital signatures to provide non-repudiation of signing
    -- actions (also called @contentCommitment@). Renders as @\"nonRepudiation\"@.
    NonRepudiation
  | -- | Enciphering private or secret keys (key transport). Renders as
    -- @\"keyEncipherment\"@.
    KeyEncipherment
  | -- | Directly enciphering raw user data without an intermediate symmetric
    -- cipher. Renders as @\"dataEncipherment\"@.
    DataEncipherment
  | -- | Key agreement protocols (e.g. Diffie-Hellman). Renders as
    -- @\"keyAgreement\"@.
    KeyAgreement
  | -- | Verifying signatures on public-key certificates. Renders as
    -- @\"keyCertSign\"@.
    KeyCertSign
  | -- | Verifying signatures on certificate revocation lists. Renders as
    -- @\"cRLSign\"@.
    CRLSign
  | -- | Enciphering data only during key agreement (used with 'KeyAgreement').
    -- Renders as @\"encipherOnly\"@.
    EncipherOnly
  | -- | Deciphering data only during key agreement (used with 'KeyAgreement').
    -- Renders as @\"decipherOnly\"@.
    DecipherOnly
  deriving (Eq, Show, Ord, Enum, Bounded)


instance ToBuilder KeyUsageBit Builder where
  toBuilder DigitalSignature = "digitalSignature"
  toBuilder NonRepudiation   = "nonRepudiation"
  toBuilder KeyEncipherment  = "keyEncipherment"
  toBuilder DataEncipherment = "dataEncipherment"
  toBuilder KeyAgreement     = "keyAgreement"
  toBuilder KeyCertSign      = "keyCertSign"
  toBuilder CRLSign          = "cRLSign"
  toBuilder EncipherOnly     = "encipherOnly"
  toBuilder DecipherOnly     = "decipherOnly"


{- | Represents the 'KeyUsage' extension

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 RFC 5280 §4.2.1.3>.
-}
type KeyUsage = NES.NESet KeyUsageBit


instance HasOID KeyUsage where
  extensionOID _ = 2 :| [5, 29, 15]


instance ToBuilder KeyUsage Builder where
  toBuilder = intersperseCommas . fmap toBuilder . NES.toList
