# simplesamlphp-module-attributelimit

A SimpleSAMLphp authentication processing filter for whitelisting which attributes the SimpleSAMLphp SP will allow to pass on the final service.

## DynamicAttributeLimit

The `attributelimit:DynamicAttributeLimit` is a SimpleSAMLphp authentication processing filter for limiting which attributes are passed on.

### Configuration

To configure the module you need to define the name of the allowed attribute(s) as value(s) inside the array which the module has been defined.

### Example configuration

```php
authproc = array(
    ...
    92 => array(
        'class' => 'core:DynamicAttributeLimit',
        'distinguishedName',
        'displayName',
        'eduPersonAssurance',
        'eduPersonScopedAffiliation',
        'eduPersonEntitlement',
        'sn',
        'mail',
        'givenName',
        'eduPersonUniqueId',
        'uid',
        'schacHomeOrganization',
    ),
```

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
