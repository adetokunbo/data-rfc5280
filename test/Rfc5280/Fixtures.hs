{- |
Module      : Rfc5280.Fixtures
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Shared test helpers for X.509 extension test suites.

'testIP' and 'testEmail' lift external-library decoders that use 'Maybe' and
@Either String@ respectively into 'MonadFail', producing a clear failure
message when decoding fails.
-}
module Rfc5280.Fixtures
  ( testIP
  , testEmail
  )
where

import Data.ByteString (ByteString)
import Data.Rfc5280.Assert (assertJust)
import Data.Text (Text)
import qualified Data.Text as T
import Net.IP (IP)
import qualified Net.IP as IP
import Text.Email.Validate (EmailAddress, validate)


-- | Decode an IP address, failing with a descriptive message if invalid.
testIP :: (MonadFail m) => Text -> m IP
testIP t = assertJust ("could not decode IP address: " <> T.unpack t) (IP.decode t)


-- | Parse an email address, failing with a descriptive message if invalid.
testEmail :: (MonadFail m) => ByteString -> m EmailAddress
testEmail bs =
  either (\e -> fail $ "invalid email address: " <> e) pure (validate bs)
