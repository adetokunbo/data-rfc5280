{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.GeneralName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'GeneralName', the common name type used across several X.509
extensions, including SubjectAltName and AuthorityInfoAccess.

'DirectoryName', 'OtherName', x400Address, and ediPartyName are not yet
modelled.
-}
module DataType.X509.Extension.GeneralName
  ( GeneralName (..)
  ) where

import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder, byteString, intDec)
import Data.Foldable (foldl')
import Data.List.NonEmpty (NonEmpty (..))
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Net.IP (IP)
import qualified Net.IP as IP
import Text.Email.Validate (EmailAddress)
import qualified Text.Email.Validate as Email
import Text.URI (URI)
import qualified Text.URI as URI

import DataType.X509.Extension (OID)


{- | A general name as defined in RFC 5280 §4.1.2.6.

Used in extensions such as SubjectAltName and AuthorityInfoAccess.
-}
data GeneralName
  = DNSName Text
  -- ^ A DNS hostname. Rendered as @DNS:\<name\>@.
  | IPAddr IP
  -- ^ An IPv4 or IPv6 address. Rendered as @IP:\<address\>@.
  | EmailAddr EmailAddress
  -- ^ An email address. Rendered as @email:\<address\>@.
  | URIName URI
  -- ^ A URI. Rendered as @URI:\<uri\>@.
  | RegisteredID OID
  -- ^ An ASN.1 registered object identifier. Rendered as @RID:\<oid\>@.
  deriving (Eq, Show)


instance ToBuilder GeneralName Builder where
  toBuilder (DNSName t)      = "DNS:" <> byteString (TE.encodeUtf8 t)
  toBuilder (IPAddr ip)      = "IP:" <> byteString (TE.encodeUtf8 (IP.encode ip))
  toBuilder (EmailAddr addr) = "email:" <> byteString (Email.toByteString addr)
  toBuilder (URIName uri)    = "URI:" <> byteString (TE.encodeUtf8 (URI.render uri))
  toBuilder (RegisteredID o) = "RID:" <> oidBuilder o


oidBuilder :: OID -> Builder
oidBuilder = intersperseWith "." . fmap intDec


intersperseWith :: Builder -> NonEmpty Builder -> Builder
intersperseWith sep (x :| xs) = x <> foldl' (\acc y -> acc <> sep <> y) "" xs
