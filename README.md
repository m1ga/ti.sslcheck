# SSL Check

Titanium module to get infos about the SSL / TLS certificate.

## Events

* sslCheck (on the `securityManager` proxy)

### Event Properties

|Name|Android|iOS|
|-|-|-|
|`fingerprint`|✅|✅|
|`issuedByCName`|✅|⚪️|
|`issuedByDName`|✅|✅|
|`issuedByOName`|✅|⚪️|
|`issuedByUName`|✅|⚪️|
|`issuedToCName`|✅|⚪️|
|`issuedToDName`|✅|⚪️|
|`issuedToOName`|✅|⚪️|
|`issuedToUName`|✅|⚪️|
|`validNotAfter`|✅|⚪️|
|`validNotBefore`|✅|⚪️|

## Usage

Same as the appcelerator.https module: create a `createSecurityManager` and attach it to `securityManager` of your HTTPClient connection.
_Note:_ `securityManager` is "creation only".

## License

MIT

## Example

See <a href="./example/app.js">example/app.js</a> for details
