{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Data.Rfc5280.KeyUsage
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides the 'KeyUsage' extension type.
-}
module Data.Rfc5280.KeyUsage
  ( KeyUsageBit (..)
  , KeyUsage
  )
where

import Data.List.NonEmpty (NonEmpty (..))
import Data.Rfc5280.HasOID (HasOID (..))
import Data.Rfc5280.Internal (RenderConfig (..), intersperseCommas)
import qualified Data.Set.NonEmpty as NES


{- | Represents the bits that can set for @KeyUsage@

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 RFC 5280 §4.2.1.3>.
-}
data KeyUsageBit
  = {- | Verifying digital signatures other than signatures on certificates or
    CRLs. Renders as @\"digitalSignature\"@.
    -}
    DigitalSignature
  | {- | Verifying digital signatures to provide non-repudiation of signing
    actions (also called @contentCommitment@). Renders as @\"nonRepudiation\"@.
    -}
    NonRepudiation
  | {- | Enciphering private or secret keys (key transport). Renders as
    @\"keyEncipherment\"@.
    -}
    KeyEncipherment
  | {- | Directly enciphering raw user data without an intermediate symmetric
    cipher. Renders as @\"dataEncipherment\"@.
    -}
    DataEncipherment
  | {- | Key agreement protocols (e.g. Diffie-Hellman). Renders as
    @\"keyAgreement\"@.
    -}
    KeyAgreement
  | {- | Verifying signatures on public-key certificates. Renders as
    @\"keyCertSign\"@.
    -}
    KeyCertSign
  | {- | Verifying signatures on certificate revocation lists. Renders as
    @\"cRLSign\"@.
    -}
    CRLSign
  | {- | Enciphering data only during key agreement (used with 'KeyAgreement').
    Renders as @\"encipherOnly\"@.
    -}
    EncipherOnly
  | {- | Deciphering data only during key agreement (used with 'KeyAgreement').
    Renders as @\"decipherOnly\"@.
    -}
    DecipherOnly
  deriving (Eq, Show, Ord, Enum, Bounded)


instance RenderConfig KeyUsageBit where
  renderBuilder DigitalSignature = "digitalSignature"
  renderBuilder NonRepudiation = "nonRepudiation"
  renderBuilder KeyEncipherment = "keyEncipherment"
  renderBuilder DataEncipherment = "dataEncipherment"
  renderBuilder KeyAgreement = "keyAgreement"
  renderBuilder KeyCertSign = "keyCertSign"
  renderBuilder CRLSign = "cRLSign"
  renderBuilder EncipherOnly = "encipherOnly"
  renderBuilder DecipherOnly = "decipherOnly"


{- | Represents the 'KeyUsage' extension

See <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 RFC 5280 §4.2.1.3>.
-}
type KeyUsage = NES.NESet KeyUsageBit


instance HasOID KeyUsage where
  extensionOID _ = 2 :| [5, 29, 15]


instance RenderConfig KeyUsage where
  renderBuilder = intersperseCommas . fmap renderBuilder . NES.toList
