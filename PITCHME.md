test

---

```ruby
require 'active_support/concern'

module SignedApiRequestValidation
  extend ActiveSupport::Concern

  cattr_accessor :min_api_version_to_validate_hashed_api_request, :secret_shared_keys
  @@min_api_version_to_validate_hashed_api_request, @@secret_shared_keys =
    InitRequestSignatureVerification.init(FB::Config, ApiVersion.latest)

  included do
    before_action :validate_request_hash!
  end

  def validate_request_hash!
    return unless activate_signed_request_access_control?
    return if api_version < @@min_api_version_to_validate_hashed_api_request

    signed_correctly, err = RequestSignature.request_signed_correctly?(
      request_timestamp:            request.env['HTTP_X_TS'],
      request_signature_to_verify:  request.env['HTTP_X_SIG'],
      api_version:                  api_version,
      real_device_token:            real_device_token,
      secret_shared_keys:           @@secret_shared_keys
    )
    if !signed_correctly && !FB::Config.emulate_hashed_api_request_validation?
      raise ERRORS[err]
    end
  end

  class InvalidRequestHashError    < StandardError; end
  class SignatureDoesNotMatchError < InvalidRequestHashError; end
  class TimestampOutdatedError     < InvalidRequestHashError; end
  class HeadersMissingError        < InvalidRequestHashError; end

  ERRORS = {
    signature_does_not_match: SignatureDoesNotMatchError,
    timestamp_outdated:       TimestampOutdatedError,
    headers_missing:          HeadersMissingError
  }
end
```
