# simplesamlphp-module-attributelimit

A SimpleSAMLphp authentication processing filter for whitelisting which attributes the SimpleSAMLphp IdP will allow to pass on the final service.

## DynamicAttributeLimit

The `attributelimit:DynamicAttributeLimit` is a SimpleSAMLphp authentication processing filter for limiting which attributes are passed on.

### Configuration

The following authproc filter configuration options are supported:

- `allowedAttributes`: Optional, an array of strings that contains the attribute names that the module will allow to pass on. Also, there is support to filter the attribute values usign regex.
- `eppnFromIdp`: Optional, an array of strings that contains the entityID of the IdPs that release `eduPersonPrincipalName`.
- `eppnToSp`: Optional, an array of strings that contains the entityID of the SPs that request for `eduPersonPrincipalName`.

### Example configuration

```php
authproc = array(
    ...
    XX => [
        'class' => 'attributelimit:DynamicAttributeLimit',
        'allowedAttributes' => [
            'displayName',
            'eduPersonEntitlement' => [
                'regex' => true,
                '/^urn:mace:egi.eu:/i',
            ],
        ],
        'eppnFromIdp' => [
            'idpEntityId01',
            'idpEntityId02',
        ],
        'eppnToSp' => [
            'spEntityId01',
            'spEntityId02',
            'spEntityId03',
        ],
    ],

```

## Compatibility matrix

This table matches the module version with the supported SimpleSAMLphp version.

| Module | SimpleSAMLphp |
| :----: | :-----------: |
|  v1.0  |     v1.14     |
|  v2.0  |     v1.17     |

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
