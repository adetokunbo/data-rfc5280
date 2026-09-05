{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : Data.Rfc5280.GeneralName
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides 'GeneralName', the common name type used across several X.509
extensions, including SubjectAltName and AuthorityInfoAccess.

'DirectoryName', x400Address, and ediPartyName are not yet modelled.
-}
module Data.Rfc5280.GeneralName
  ( GeneralName (DNS, IPAddr, EmailAddr, URIName, Other)
  , pattern RegisteredID
  , DnsName
  , dnsNameText
  , OtherName
  , pattern OtherName
  , onTypeId
  , onEncoding
  , onValue
  , Asn1StringType (..)
  , DNSNameError (..)
  , OtherNameError (..)
  , mkDnsName
  , mkDnsConstraint
  , mkRegisteredID
  , mkOtherName
  , mkOther
  )
where

import Data.Bifunctor (first)
import Data.ByteString.Builder (byteString)
import Data.Char (isAlphaNum, isAscii)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Rfc5280.Internal (OID, OIDError, RenderConfig (..), mkOID, oidBuilder)
import Net.IP (IP)
import qualified Net.IP as IP
import Text.Email.Validate (EmailAddress)
import qualified Text.Email.Validate as Email
import Text.URI (URI)
import qualified Text.URI as URI


{- | A validated DNS hostname.

The constructor is not exported; use 'mkDnsName' for standard hostnames or
'mkDnsConstraint' for name-constraint subtree names (which may have a leading
dot such as @\".example.com\"@).
-}
newtype DnsName = DnsName Text
  deriving (Eq, Show)


-- | Extract the underlying 'Text' from a 'DnsName'.
dnsNameText :: DnsName -> Text
dnsNameText (DnsName t) = t


{- | A general name as defined in RFC 5280 §4.1.2.6.

Used in extensions such as SubjectAltName and AuthorityInfoAccess.
-}
data GeneralName
  = {- | A DNS hostname. Rendered as @DNS:\<name\>@. Construct via 'mkDnsName'.
    -}
    DNS !DnsName
  | -- | An IPv4 or IPv6 address. Rendered as @IP:\<address\>@.
    IPAddr !IP
  | -- | An email address. Rendered as @email:\<address\>@.
    EmailAddr !EmailAddress
  | -- | A URI. Rendered as @URI:\<uri\>@.
    URIName !URI
  | -- Internal constructor; exposed for matching via 'pattern RegisteredID'.
    RegisteredID_ !OID
  | {- | An arbitrary other name. Rendered as
    @otherName:\<oid\>;\<type\>:\<value\>@, where @\<type\>@ is the
    OpenSSL tag string for the 'Asn1StringType'.
    -}
    Other !OtherName
  deriving (Eq, Show)


{- | Match a 'GeneralName' carrying an ASN.1 registered object identifier.

This is a unidirectional pattern: it can be used in pattern matches but not
to construct a 'GeneralName'. Use 'mkRegisteredID' to construct one, which
validates the OID arcs via 'mkOID'.
-}
pattern RegisteredID :: OID -> GeneralName
pattern RegisteredID o <- RegisteredID_ o

{-# COMPLETE DNS, IPAddr, EmailAddr, URIName, RegisteredID, Other #-}


{- | The fields of an @otherName@ general name (RFC 5280 §4.1.2.6).

Carries the type OID, the ASN.1 string encoding, and the string value.
The 'MkOtherName' constructor is not exported; use 'mkOtherName' to construct
a value and 'pattern OtherName' to match one.
-}
data OtherName = MkOtherName
  { onTypeId :: !OID
  -- ^ OID identifying the name type.
  , onEncoding :: !Asn1StringType
  -- ^ ASN.1 string encoding for the value.
  , onValue :: !Text
  -- ^ The string value.
  }
  deriving (Eq, Show)


{- | Match an 'OtherName' value.

This is a unidirectional pattern: it can be used in pattern matches but not
to construct an 'OtherName'. Use 'mkOtherName' to construct one, which
validates the OID arcs and checks the value against the declared encoding.
-}
pattern OtherName :: OID -> Asn1StringType -> Text -> OtherName
pattern OtherName oid enc val <-
  MkOtherName {onTypeId = oid, onEncoding = enc, onValue = val}

{-# COMPLETE OtherName #-}


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
  = -- | UTF-8 encoding. Rendered as @UTF8@.
    UTF8String
  | -- | ASCII (IA5) encoding. Rendered as @IA5@.
    IA5String
  | -- | PrintableString encoding. Rendered as @PRINTABLE@.
    PrintableString
  | -- | BMP (UCS-2) encoding. Rendered as @BMP@.
    BMPString
  deriving (Eq, Show)


instance RenderConfig Asn1StringType where
  renderBuilder UTF8String = "UTF8"
  renderBuilder IA5String = "IA5"
  renderBuilder PrintableString = "PRINTABLE"
  renderBuilder BMPString = "BMP"


instance RenderConfig GeneralName where
  renderBuilder (DNS (DnsName t)) = "DNS:" <> byteString (TE.encodeUtf8 t)
  renderBuilder (IPAddr ip) = "IP:" <> byteString (TE.encodeUtf8 (IP.encode ip))
  renderBuilder (EmailAddr addr) = "email:" <> byteString (Email.toByteString addr)
  renderBuilder (URIName uri) = "URI:" <> byteString (TE.encodeUtf8 (URI.render uri))
  renderBuilder (RegisteredID_ o) = "RID:" <> oidBuilder o
  renderBuilder (Other on) =
    "otherName:"
      <> oidBuilder (onTypeId on)
      <> ";"
      <> renderBuilder (onEncoding on)
      <> ":"
      <> byteString (TE.encodeUtf8 (onValue on))


-- | Failure modes for 'mkDnsName' and 'mkDnsConstraint'.
data DNSNameError
  = -- | The name or a label within it is empty.
    NameEmpty
  | -- | The name exceeds 253 characters.
    NameTooLong
  | -- | A label exceeds 63 characters.
    LabelTooLong
  | -- | A label starts with a hyphen.
    LabelLeadingHyphen
  | -- | A label ends with a hyphen.
    LabelTrailingHyphen
  | -- | A label contains a character outside @[A-Za-z0-9-]@.
    LabelInvalidChar
  deriving (Eq, Show)


{- | Construct a 'DnsName', validating against RFC 1123 hostname rules.

Returns @Left@ with a 'DNSNameError' if the name is invalid. Accepts a
wildcard @*@ as the first label (e.g. @\"*.example.com\"@). IDNA\/punycode
encoding of Unicode hostnames must be done by the caller before passing to
this function.

To construct a name-constraint subtree name with a leading dot (e.g.
@\".example.com\"@), use 'mkDnsConstraint' instead.
-}
mkDnsName :: Text -> Either DNSNameError DnsName
mkDnsName t
  | T.null t = Left NameEmpty
  | T.length t > 253 = Left NameTooLong
  | otherwise = validateLabels (T.splitOn "." t) >> Right (DnsName t)
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


{- | Construct a 'DnsName' for use as an RFC 5280 name-constraint subtree.

Accepts an optional leading dot (e.g. @\".example.com\"@), which denotes the
domain and all its subdomains. The remainder after stripping the leading dot
must satisfy the same RFC 1123 rules as 'mkDnsName'.

Use 'mkDnsName' for ordinary hostname values; use this function only when
constructing a 'NameConstraints' subtree entry.
-}
mkDnsConstraint :: Text -> Either DNSNameError DnsName
mkDnsConstraint t = case T.stripPrefix "." t of
  Just rest -> mkDnsName rest >> Right (DnsName t)
  Nothing -> mkDnsName t


-- | Failure modes for 'mkOtherName'.
data OtherNameError
  = -- | The OID arcs are invalid; see 'OIDError'.
    InvalidOID
  | -- | The value contains a code point above U+007F.
    IA5NonAscii
  | -- | The value contains a character outside the PrintableString alphabet.
    PrintableInvalidChar
  | -- | The value contains a code point above U+FFFF.
    BMPNonBMP
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
  return (MkOtherName oid enc val)
 where
  validateEncoding UTF8String _ = Right ()
  validateEncoding IA5String t
    | T.all (\c -> fromEnum c <= 127) t = Right ()
    | otherwise = Left IA5NonAscii
  validateEncoding PrintableString t
    | T.all isPrintableChar t = Right ()
    | otherwise = Left PrintableInvalidChar
  validateEncoding BMPString t
    | T.all (\c -> fromEnum c <= 0xFFFF) t = Right ()
    | otherwise = Left BMPNonBMP

  isPrintableChar c = (isAscii c && isAlphaNum c) || c `elem` (" '()+,-./:=?" :: String)


{- | Construct a 'GeneralName' carrying a validated ASN.1 registered object
identifier.

The OID arcs are validated via 'mkOID'. Returns @Left 'OIDError'@ if
validation fails.
-}
mkRegisteredID :: Int -> [Int] -> Either OIDError GeneralName
mkRegisteredID firstArc restArcs = RegisteredID_ <$> mkOID firstArc restArcs


{- | Construct a @'Other' 'OtherName'@ 'GeneralName', validating the OID and
encoding in the same way as 'mkOtherName'.
-}
mkOther :: Int -> [Int] -> Asn1StringType -> Text -> Either OtherNameError GeneralName
mkOther firstArc restArcs enc val = Other <$> mkOtherName firstArc restArcs enc val
