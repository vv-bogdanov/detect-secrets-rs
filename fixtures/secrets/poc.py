# Synthetic POC fixture. Values are intentionally fake and use push-safe
# example payloads rather than real provider token shapes.

base64_secret = 'dGhpc2lzbm90cmVhbHNlY3JldHZhbHVl'
hex_secret = '00112233445566778899aabbccddeeff'

aws_access_key = 'AKIAIOSFODNN7EXAMPLE'
aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

github_token = 'ghp_example_token_for_fixture_only'
gitlab_token = 'glpat-example'
npm_token = '//registry.npmjs.org/:_authToken=npm_example_token_for_fixture'
jwt_token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.'
slack_token = 'xoxb-not-a-real-token'

private_key = '''
-----BEGIN RSA PRIVATE KEY-----
not-a-real-key
-----END RSA PRIVATE KEY-----
'''

allowlisted_aws = 'AKIAIOSFODNN7EXAMPLE'  # pragma: allowlist secret

# pragma: allowlist nextline secret
allowlisted_github = 'ghp_example_allowlisted_fixture_token'
