# Yoti Go SDK

[![Go Report Card](https://goreportcard.com/badge/github.com/getyoti/yoti-go-sdk)](https://goreportcard.com/report/github.com/getyoti/yoti-go-sdk)
[![Build Status](https://travis-ci.com/getyoti/yoti-go-sdk.svg?branch=master)](https://travis-ci.com/getyoti/yoti-go-sdk)
[![GoDoc](https://godoc.org/github.com/getyoti/yoti-go-sdk?status.svg)](https://godoc.org/github.com/getyoti/yoti-go-sdk)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://github.com/getyoti/yoti-go-sdk/blob/master/LICENSE.md)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=getyoti%3Ago&metric=coverage)](https://sonarcloud.io/dashboard?id=getyoti%3Ago)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=getyoti%3Ago&metric=bugs)](https://sonarcloud.io/dashboard?id=getyoti%3Ago)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=getyoti%3Ago&metric=code_smells)](https://sonarcloud.io/dashboard?id=getyoti%3Ago)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=getyoti%3Ago&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=getyoti%3Ago)

Welcome to the Yoti Go SDK. This repo contains the tools and step by step instructions you need to quickly integrate your Go back-end with Yoti so that your users can share their identity details with your application in a secure and trusted way.

## Table of Contents

1) [An Architectural view](#an-architectural-view) -
High level overview of integration

1) [Installing the SDK](#installing-the-sdk) -
How to install our SDK

1) [SDK Project import](#sdk-project-import) -
How to install the SDK to your project

1) [Configuration](#configuration) -
How to initialise your configuration

1) [Profile Retrieval](#profile-retrieval) -
How to retrieve a Yoti profile using the one time use token

1) [Handling users](#handling-users) -
How to manage users

1) [Sandbox](#sandbox) -
How to use the Yoti sandbox service to test your application

1) [AML Integration](#aml-integration) -
How to integrate with Yoti's AML (Anti Money Laundering) service

1) [Running the example](#running-the-profile-example) -
Running the profile example project

1) [API Coverage](#api-coverage) -
Attributes defined

1) [Support](#support) -
Please feel free to reach out

1) [References](#references)

## An Architectural View

Before you start your integration, here is a bit of background on how the integration works. To integrate your application with Yoti, your back-end must expose a GET endpoint that Yoti will use to forward tokens.
The endpoint is configured in the [Yoti Hub](https://hub.yoti.com) where you create/update your application. For more information on how to create an application please see [integration steps](https://developers.yoti.com/yoti-app/web-integration#integration-steps).

The image below shows how your application back-end and Yoti integrate into the context of a Login flow.
Yoti SDK carries out for you steps 6, 7 ,8 and the profile decryption in step 9.

![alt text](login_flow.png "Login flow")

Yoti also allows you to enable user details verification from your mobile app by means of the Android (TBA) and iOS (TBA) SDKs. In that scenario, your Yoti-enabled mobile app is playing both the role of the browser and the Yoti app. Your back-end doesn't need to handle these cases in a significantly different way. You might just decide to handle the `User-Agent` header in order to provide different responses for desktop and mobile clients.

## Requirements

Supported Go Versions:
- 1.11+

## Installing the SDK

_As of version **2.4.0**, [modules](https://github.com/golang/go/wiki/Modules) are used. This means it's not necessary to get a copy or fetch all dependencies, as the Go toolchain will fetch them as necessary. You can simply add a `require github.com/getyoti/yoti-go-sdk/v3` to go.mod._

## SDK Project import

You can reference the project URL by adding the following import:

```Go
import "github.com/getyoti/yoti-go-sdk/v3"
```

## Configuration

The YotiClient is the SDK entry point. To initialise it you need include the following snippet inside your endpoint initialisation section:

```Go
clientSdkID := "your-client-sdk-id"
key, err := ioutil.ReadFile("path/to/your-application-pem-file.pem")
if err != nil {
    // handle key load error
}

client, err := yoti.NewClient(
    clientSdkID,
    key)
```

Where:

* `"your-client-sdk-id"` is the SDK Client Identifier generated by Yoti Hub in the Key tab when you create your application.

* `path/to/your-application-pem-file.pem` is the path to the application pem file. It can be downloaded from the Keys tab in the [Yoti Hub](https://hub.yoti.com/).

Please do not open the pem file as this might corrupt the key and you will need regenerate your key.

Keeping your settings and access keys outside your repository is highly recommended. You can use a package like [godotenv](https://github.com/joho/godotenv) to manage environment variables more easily.

## Profile Retrieval

When your application receives a one time use token via the exposed endpoint (it will be assigned to a query string parameter named `token`), you can easily retrieve the activity details by adding the following to your endpoint handler:

```Go
activityDetails, err := client.GetActivityDetails(yotiOneTimeUseToken)
if err != nil {
  // handle unhappy path
}
```

## Handling Errors
If a network error occurs that can be handled by resending the request,
the error returned by the SDK will implement the temporary error interface.
This can be tested for using either `errors.Is` or a type assertion, and resent.

```Go
while true {
  activityDetails, err := client.GetActivityDetails(token)
  var temp interface{ Temporary() bool }
  if !errors.Is(err, &temp) {
    break
  }
  // Log the temporary error as a warning
}
```

### Profile

You can then get the user profile from the activityDetails struct:

```Go
var rememberMeID string = activityDetails.RememberMeID()
var parentRememberMeID string = activityDetails.ParentRememberMeID()
var userProfile yoti.Profile = activityDetails.UserProfile

var selfie = userProfile.Selfie().Value()
var givenNames string = userProfile.GivenNames().Value()
var familyName string = userProfile.FamilyName().Value()
var fullName string = userProfile.FullName().Value()
var mobileNumber string = userProfile.MobileNumber().Value()
var emailAddress string = userProfile.EmailAddress().Value()
var address string = userProfile.Address().Value()
var gender string = userProfile.Gender().Value()
var nationality string = userProfile.Nationality().Value()
var dateOfBirth *time.Time
dobAttr, err := userProfile.DateOfBirth()
if err != nil {
    // handle error
} else {
    dateOfBirth = dobAttr.Value()
}
var structuredPostalAddress map[string]interface{}
structuredPostalAddressAttribute, err := userProfile.StructuredPostalAddress()
if err != nil {
    // handle error
} else {
    structuredPostalAddress := structuredPostalAddressAttribute.Value().(map[string]interface{})
}
```

If you have chosen Verify Condition on the Yoti Hub with the age condition of "Over 18", you can retrieve the user information with the generic .GetAttribute method, which requires the result to be cast to the original type:

```Go
userProfile.GetAttribute("age_over:18").Value().(string)
```

GetAttribute returns an interface, the value can be acquired through a type assertion.

### Anchors, Sources and Verifiers

An `Anchor` represents how a given Attribute has been _sourced_ or _verified_.  These values are created and signed whenever a Profile Attribute is created, or verified with an external party.

For example, an attribute value that was _sourced_ from a Passport might have the following values:

`Anchor` property | Example value
-----|------
type | SOURCE
value | PASSPORT
subType | OCR
signedTimestamp | 2017-10-31, 19:45:59.123789

Similarly, an attribute _verified_ against the data held by an external party will have an `Anchor` of type _VERIFIER_, naming the party that verified it.

From each attribute you can retrieve the `Anchors`, and subsets `Sources` and `Verifiers` (all as `[]*anchor.Anchor`) as follows:

```Go
givenNamesAnchors := userProfile.GivenNames().Anchors()
givenNamesSources := userProfile.GivenNames().Sources()
givenNamesVerifiers := userProfile.GivenNames().Verifiers()
```

You can also retrieve further properties from these respective anchors in the following way:

```Go
var givenNamesFirstAnchor *anchor.Anchor = givenNamesAnchors[0]

var anchorType anchor.Type = givenNamesFirstAnchor.Type()
var signedTimestamp *time.Time = givenNamesFirstAnchor.SignedTimestamp().Timestamp()
var subType string = givenNamesFirstAnchor.SubType()
var value string = givenNamesFirstAnchor.Value()
```

## Handling Users

When you retrieve the user profile, you receive a user ID generated by Yoti exclusively for your application.
This means that if the same individual logs into another app, Yoti will assign her/him a different ID.
You can use this ID to verify whether (for your application) the retrieved profile identifies a new or an existing user.
Here is an example of how this works:

```Go
activityDetails, err := client.GetActivityDetails(yotiOneTimeUseToken)
if err == nil {
    user := YourUserSearchFunction(activityDetails.RememberMeID())
    if user != nil {
        // handle login
    } else {
      // handle registration
    }
} else {
    // handle unhappy path
}
```

Where `yourUserSearchFunction` is a piece of logic in your app that is supposed to find a user, given a RememberMeID.
No matter if the user is a new or an existing one, Yoti will always provide her/his profile, so you don't necessarily need to store it.

The `profile` object provides a set of attributes corresponding to user attributes. Whether the attributes are present or not depends on the settings you have applied to your app on Yoti Hub.

## Sandbox

- [Yoti Profile Sandbox](_docs/PROFILE_SANDBOX.md)

## Running the Profile Example

The profile retrieval example can be found in the [_examples folder](_examples).

* Change directory to the profile example folder: `cd _examples/profile`
* On the [Yoti Hub](https://hub.yoti.com/):
  * Set the application domain of your app to `localhost:8080`
  * Set the scenario callback URL to `/profile`
* Rename the [.env.example](_examples/profile/.env.example) file to `.env` and fill in the required configuration values (mentioned in the [Configuration](#configuration) section)
* Install the dependencies with `go get`
* Start the server with `go run main.go certificatehelper.go`

Visiting `https://localhost:8080/` should show a Yoti Connect button

## API Coverage

* [X] Activity Details
  * [X] Remember Me ID `RememberMeID()`
  * [X] Parent Remember Me ID `ParentRememberMeID()`
  * [X] User Profile `UserProfile`
    * [X] Selfie `Selfie()`
    * [X] Selfie Base64 URL `Selfie().Value().Base64URL()`
    * [X] Given Names `GivenNames()`
    * [X] Family Name `FamilyName()`
    * [X] Full Name `FullName()`
    * [X] Mobile Number `MobileNumber()`
    * [X] Email Address `EmailAddress()`
    * [X] Date of Birth `DateOfBirth()`
    * [X] Postal Address `Address()`
    * [X] Structured Postal Address `StructuredPostalAddress()`
    * [X] Gender `Gender()`
    * [X] Nationality `Nationality()`

## Support

For any questions or support please email [sdksupport@yoti.com](mailto:sdksupport@yoti.com).
Please provide the following to get you up and working as quickly as possible:

* Computer type
* OS version
* Version of Go being used
* Screenshot

Once we have answered your question we may contact you again to discuss Yoti products and services. If you’d prefer us not to do this, please let us know when you e-mail.

## References

* [AES-256 symmetric encryption][]
* [RSA pkcs asymmetric encryption][]
* [Protocol buffers][]
* [Base64 data][]

[AES-256 symmetric encryption]:   https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[RSA pkcs asymmetric encryption]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
[Protocol buffers]:               https://en.wikipedia.org/wiki/Protocol_Buffers
[Base64 data]:                    https://en.wikipedia.org/wiki/Base64
