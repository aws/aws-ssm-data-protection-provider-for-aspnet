## Release 2025-03-04

### Amazon.AspNetCore.DataProtection.SSM (4.0.0-preview.4)
* Update .NET SDK dependencies to v4.0.0-preview.8

## Release 2025-02-12

### Amazon.AspNetCore.DataProtection.SSM (3.5.0)
* Updated SSMXmlRepository to implement IDeletableXmlRepository for .NET 9 target.

## Release 2024-12-16

### Amazon.AspNetCore.DataProtection.SSM (3.4.0)
* Update .NET target to use version 8.0.11 of Microsoft.AspNetCore.DataProtection
* Update Microsoft.AspNetCore.DataProtection dependency to address transitive dependencies vulnerabilities
* Replace .NET targets less then .NET 8 with a .NET Standard 2.0 target

## Release 2024-12-10

### Amazon.AspNetCore.DataProtection.SSM (4.0.0-preview.3)
* Update Microsoft.AspNetCore.DataProtection dependency to address transitive dependencies vulnerabilities
* Replace .NET targets less then .NET 8 with a .NET Standard 2.0 target

## Release 2024-11-27

### Amazon.AspNetCore.DataProtection.SSM (3.3.0)
* Update Microsoft.AspNetCore.DataProtection dependency to address transitive dependencies vulnerabilities
* Replace .NET targets less then .NET 8 with a .NET Standard 2.0 target

## Release 2024-10-24

### Amazon.AspNetCore.DataProtection.SSM (4.0.0-preview.2)
* Mark the assembly trimmable
* Enable Source Link

## Release 2024-10-09

### Amazon.AspNetCore.DataProtection.SSM (4.0.0-preview.1)
* Updated the .NET SDK dependencies to the latest version 4.0.0-preview.3

## Release 2024-04-20

### Amazon.AspNetCore.DataProtection.SSM (3.2.1)
* Update User-Agent string

## Release 2023-11-14

### Amazon.AspNetCore.DataProtection.SSM (3.2.0)
* Add .NET 8 target
* Added support of Intelligent-Tiering parameter tier
* Pull request [#60](https://github.com/aws/aws-ssm-data-protection-provider-for-aspnet/pull/60) Fixed logging paramter casing for structured logging support. Thanks [Martin Costello](https://github.com/martincostello)

## Release 2023-02-03

### Amazon.AspNetCore.DataProtection.SSM (3.1.1)
* Update dependency of Microsoft.AspNetCore.DataProtection.Extensions to use the version that comes with the .NET runtime instead of bring in a specific version.

## Release 2023-02-03

### Amazon.AspNetCore.DataProtection.SSM (3.1.0)
* Merged PR [#48](https://github.com/aws/aws-ssm-data-protection-provider-for-aspnet/pull/48) Add support for adding tags to SSM parameters. Thanks [Martin Costello](https://github.com/martincostello)
* Merged PR [#49](https://github.com/aws/aws-ssm-data-protection-provider-for-aspnet/pull/49) Fix up code analysis warnings. Thanks [Martin Costello](https://github.com/martincostello)


## Release 2022-09-22

### Amazon.AspNetCore.DataProtection.SSM (3.0.0)
* Breaking change remove target .NET Standard 2.0 and add .NET Core 3.1 and .NET 6
* Merged PR [#42](https://github.com/aws/aws-ssm-data-protection-provider-for-aspnet/pull/42) Updated AWS and Microsoft dependencies. Thanks [Tristan Hyams](https://github.com/houseofcat)
	
## Release 2021-03-30

### Amazon.AspNetCore.DataProtection.SSM (2.1.0)
* Update AWS SDK dependencies to 3.7

## Release 2020-10-09

### Amazon.AspNetCore.DataProtection.SSM (2.0.0)
* Merged PR [#21](https://github.com/aws/aws-ssm-data-protection-provider-for-aspnet/pull/21) Upgrade dependency of .netcoresetup to 3.3.101. Thanks [Yuxuan Lin](https://github.com/YuxuanLin)
* Update AWS SDK dependencies to 3.5, and update version to 2.0.0

## Release 2019-08-15

### Amazon.AspNetCore.DataProtection.SSM (1.1.0)
* Merged PR [#10](https://github.com/aws/aws-ssm-data-protection-provider-for-aspnet/pull/10) Add advanced tier usage option for large keys. Thanks [Konrad Müller](https://github.com/krdmllr)

## Release 2019-02-21

### Amazon.AspNetCore.DataProtection.SSM (1.0.1)
* Remove unnecessary dependencies

## Release 2018-12-14

### Amazon.AspNetCore.DataProtection.SSM (1.0.0)
* Initial release