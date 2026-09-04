{- |
Module      : X509.Extension.Fixtures
Copyright   : (c) 2026 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Shared test helpers for X.509 extension test suites.

'assertRight' lifts any @Either e a@ result (such as those returned by smart
constructors) into a 'MonadFail' context, producing a clear failure message on
'Left'. 'testIP' and 'testEmail' do the same for external-library decoders
that use 'Maybe' and @Either String@ respectively.
-}
module X509.Extension.Fixtures
  ( assertRight
  , testIP
  , testEmail
  )
where

import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T
import Net.IP (IP)
import qualified Net.IP as IP
import Text.Email.Validate (EmailAddress, validate)


{- | Lift an @Either e a@ result into any 'MonadFail', calling 'fail' with
'show' of the error on 'Left'.

Use this to unwrap smart-constructor results inside hspec @it@ blocks:

@
dn <- assertRight (mkDnsName "example.com")
@
-}
assertRight :: (Show e, MonadFail m) => Either e a -> m a
assertRight = either (fail . show) pure


-- | Decode an IP address, failing with a descriptive message if invalid.
testIP :: MonadFail m => Text -> m IP
testIP t =
  maybe (fail $ "could not decode IP address: " <> T.unpack t) pure (IP.decode t)


-- | Parse an email address, failing with a descriptive message if invalid.
testEmail :: MonadFail m => ByteString -> m EmailAddress
testEmail bs =
  either (\e -> fail $ "invalid email address: " <> e) pure (validate bs)
