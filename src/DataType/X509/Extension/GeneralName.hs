{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : DataType.X509.Extension.GeneralName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'GeneralName', the common name type used across several X.509
extensions, including SubjectAltName and AuthorityInfoAccess.

'DirectoryName', x400Address, and ediPartyName are not yet modelled.
-}
module DataType.X509.Extension.GeneralName
  ( GeneralName (..)
  , OtherName (..)
  , Asn1StringType (..)
  , DNSNameError (..)
  , OtherNameError (..)
  , mkDNSName
  , mkOtherName
  )
where

import Data.Bifunctor (first)
import Data.Builder (ToBuilder (..))
import Data.ByteString.Builder (Builder, byteString)
import Data.Char (isAlphaNum, isAscii)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import DataType.X509.Extension.Internal (OID, mkOID, oidBuilder)
import Net.IP (IP)
import qualified Net.IP as IP
import Text.Email.Validate (EmailAddress)
import qualified Text.Email.Validate as Email
import Text.URI (URI)
import qualified Text.URI as URI


{- | A general name as defined in RFC 5280 §4.1.2.6.

Used in extensions such as SubjectAltName and AuthorityInfoAccess.
-}
data GeneralName
  = {- | A DNS hostname. Rendered as @DNS:\<name\>@. Prefer 'mkDNSName' to
    validate the hostname before construction.
    -}
    DNSName !Text
  | -- | An IPv4 or IPv6 address. Rendered as @IP:\<address\>@.
    IPAddr !IP
  | -- | An email address. Rendered as @email:\<address\>@.
    EmailAddr !EmailAddress
  | -- | A URI. Rendered as @URI:\<uri\>@.
    URIName !URI
  | -- | An ASN.1 registered object identifier. Rendered as @RID:\<oid\>@.
    RegisteredID !OID
  | {- | An arbitrary other name. Rendered as
    @otherName:\<oid\>;\<type\>:\<value\>@, where @\<type\>@ is the
    OpenSSL tag string for the 'Asn1StringType'.
    -}
    Other !OtherName
  deriving (Eq, Show)


{- | The fields of an @otherName@ general name (RFC 5280 §4.1.2.6).

Carries the type OID, the ASN.1 string encoding, and the string value.
-}
data OtherName = OtherName
  { onTypeId   :: !OID           -- ^ OID identifying the name type.
  , onEncoding :: !Asn1StringType -- ^ ASN.1 string encoding for the value.
  , onValue    :: !Text           -- ^ The string value.
  }
  deriving (Eq, Show)


{- | The ASN.1 string encoding for an 'OtherName' value.

Covers the four types commonly used in practice for X.509 extension values.
The ASN.1 standard defines additional string types — including
'VisibleString', 'UniversalString', 'TeletexString', 'NumericString', and
'GeneralString' — but these are not modelled here because they are either
legacy types or primarily relevant to distinguished name components rather
than extension values:

* 'TeletexString' and 'UniversalString' appeared in early X.509 DN fields
  but are discouraged by RFC 5280 and superseded by 'UTF8String'.
* 'NumericString' is for digit-only fields such as the @serialNumber@ DN
  attribute; it has no common use in extension values.
* 'VisibleString' and 'GeneralString' appear only in edge cases and legacy
  structures.

For the vast majority of 'OtherName' use cases — including Microsoft UPN
(which uses 'UTF8String') and email addresses (which use 'IA5String') — the
four modelled constructors are sufficient.
-}
data Asn1StringType
  = UTF8String      -- ^ UTF-8 encoding. Rendered as @UTF8@.
  | IA5String       -- ^ ASCII (IA5) encoding. Rendered as @IA5@.
  | PrintableString -- ^ PrintableString encoding. Rendered as @PRINTABLE@.
  | BMPString       -- ^ BMP (UCS-2) encoding. Rendered as @BMP@.
  deriving (Eq, Show)


instance ToBuilder Asn1StringType Builder where
  toBuilder UTF8String      = "UTF8"
  toBuilder IA5String       = "IA5"
  toBuilder PrintableString = "PRINTABLE"
  toBuilder BMPString       = "BMP"


instance ToBuilder GeneralName Builder where
  toBuilder (DNSName t)           = "DNS:" <> byteString (TE.encodeUtf8 t)
  toBuilder (IPAddr ip)           = "IP:" <> byteString (TE.encodeUtf8 (IP.encode ip))
  toBuilder (EmailAddr addr)      = "email:" <> byteString (Email.toByteString addr)
  toBuilder (URIName uri)         = "URI:" <> byteString (TE.encodeUtf8 (URI.render uri))
  toBuilder (RegisteredID o) = "RID:" <> oidBuilder o
  toBuilder (Other on)       =
    "otherName:" <> oidBuilder (onTypeId on) <> ";" <> toBuilder (onEncoding on) <> ":" <> byteString (TE.encodeUtf8 (onValue on))


-- | Failure modes for 'mkDNSName'.
data DNSNameError
  = NameEmpty           -- ^ The name or a label within it is empty.
  | NameTooLong         -- ^ The name exceeds 253 characters.
  | LabelTooLong        -- ^ A label exceeds 63 characters.
  | LabelLeadingHyphen  -- ^ A label starts with a hyphen.
  | LabelTrailingHyphen -- ^ A label ends with a hyphen.
  | LabelInvalidChar    -- ^ A label contains a character outside @[A-Za-z0-9-]@.
  deriving (Eq, Show)


{- | Construct a 'DNSName', validating against RFC 1123 hostname rules.

Returns @Left@ with a 'DNSNameError' if the name is invalid. Accepts a
wildcard @*@ as the first label (e.g. @\"*.example.com\"@). IDNA\/punycode
encoding of Unicode hostnames must be done by the caller before passing to
this function.
-}
mkDNSName :: Text -> Either DNSNameError GeneralName
mkDNSName t
  | T.null t = Left NameEmpty
  | T.length t > 253 = Left NameTooLong
  | otherwise = validateLabels (T.splitOn "." t) >> Right (DNSName t)
 where
  validateLabels [] = Left NameEmpty
  validateLabels (l : ls) = validateFirst l >> mapM_ validateLabel ls

  validateFirst "*" = Right ()
  validateFirst l = validateLabel l

  validateLabel l
    | T.null l = Left NameEmpty
    | T.length l > 63 = Left LabelTooLong
    | otherwise =
        case (T.uncons l, T.unsnoc l) of
          (Just ('-', _), _) -> Left LabelLeadingHyphen
          (_, Just (_, '-')) -> Left LabelTrailingHyphen
          _
            | T.all isValidChar l -> Right ()
            | otherwise -> Left LabelInvalidChar

  isValidChar c = isAlphaNum c || c == '-'


-- | Failure modes for 'mkOtherName'.
data OtherNameError
  = InvalidOID          -- ^ The OID arcs are invalid; see 'OIDError'.
  | IA5NonAscii         -- ^ The value contains a code point above U+007F.
  | PrintableInvalidChar -- ^ The value contains a character outside the PrintableString alphabet.
  | BMPNonBMP           -- ^ The value contains a code point above U+FFFF.
  deriving (Eq, Show)


{- | Construct an 'OtherName', validating the OID and the text value against
the declared 'Asn1StringType' character set.

Returns @Left@ with an 'OtherNameError' if validation fails. The OID is
validated via 'mkOID'. Character-set constraints:

* 'UTF8String' — any 'Text' is accepted.
* 'IA5String' — all code points must be ≤ U+007F.
* 'PrintableString' — all characters must be in @[A-Za-z0-9 \'()+,-./:=?]@.
* 'BMPString' — all code points must be ≤ U+FFFF.
-}
mkOtherName :: Int -> [Int] -> Asn1StringType -> Text -> Either OtherNameError OtherName
mkOtherName firstArc restArcs enc val = do
  oid <- first (const InvalidOID) (mkOID firstArc restArcs)
  validateEncoding enc val
  return (OtherName oid enc val)
 where
  validateEncoding UTF8String      _ = Right ()
  validateEncoding IA5String       t
    | T.all (\c -> fromEnum c <= 127) t = Right ()
    | otherwise = Left IA5NonAscii
  validateEncoding PrintableString t
    | T.all isPrintableChar t = Right ()
    | otherwise = Left PrintableInvalidChar
  validateEncoding BMPString       t
    | T.all (\c -> fromEnum c <= 0xFFFF) t = Right ()
    | otherwise = Left BMPNonBMP

  isPrintableChar c = (isAscii c && isAlphaNum c) || c `elem` (" '()+,-./:=?" :: String)


