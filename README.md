# Yoti Go SDK

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

1) [AML Integration](#aml-integration) -
How to integrate with Yoti's AML (Anti Money Laundering) service

1) [Running the tests](#running-the-tests) -
Attributes defined

1) [Running the example](#running-the-profile-example) -
Attributes defined

1) [API Coverage](#api-coverage) -
Attributes defined

1) [Support](#support) -
Please feel free to reach out

1) [References](#references)

## An Architectural View

Before you start your integration, here is a bit of background on how the integration works. To integrate your application with Yoti, your back-end must expose a GET endpoint that Yoti will use to forward tokens.
The endpoint is configured in the [Yoti Dashboard](https://www.yoti.com/dashboard) where you create/update your application. For more information on how to create an application please check our [developer page](https://www.yoti.com/developers/documentation/#login-button-setup).

The image below shows how your application back-end and Yoti integrate into the context of a Login flow.
Yoti SDK carries out for you steps 6, 7 ,8 and the profile decryption in step 9.

![alt text](login_flow.png "Login flow")

Yoti also allows you to enable user details verification from your mobile app by means of the Android (TBA) and iOS (TBA) SDKs. In that scenario, your Yoti-enabled mobile app is playing both the role of the browser and the Yoti app. Your back-end doesn't need to handle these cases in a significantly different way. You might just decide to handle the `User-Agent` header in order to provide different responses for desktop and mobile clients.

## Installing the SDK

To download and install the Yoti SDK and its dependencies, simply run the following command from your terminal:

```Go
go get "github.com/getyoti/yoti-go-sdk"
```

## SDK Project import

You can reference the project URL by adding the following import:

```Go
import "github.com/getyoti/yoti-go-sdk"
```

## Configuration

The YotiClient is the SDK entry point. To initialise it you need include the following snippet inside your endpoint initialisation section:

```Go
sdkID := "your-sdk-id";
key, err := ioutil.ReadFile("path/to/your-application-pem-file.pem")
if err != nil {
    // handle key load error
}

client := yoti.Client{
    SdkID: sdkID,
    Key: key}
```

Where:

* `sdkID` is the SDK identifier generated by Yoti Dashboard in the Key tab when you create your app. Note this is not your Application Identifier which is needed by your client-side code.

* `path/to/your-application-pem-file.pem` is the path to the application pem file. It can be downloaded from the Keys tab in the [Yoti Dashboard](https://www.yoti.com/dashboard/applications).

Please do not open the pem file as this might corrupt the key and you will need to create a new application.

Keeping your settings and access keys outside your repository is highly recommended. You can use gems like [godotenv](https://github.com/joho/godotenv) to manage environment variables more easily.

## Profile Retrieval

When your application receives a one time use token via the exposed endpoint (it will be assigned to a query string parameter named `token`), you can easily retrieve the activity details by adding the following to your endpoint handler:

```Go
activityDetails, errStrings := client.GetActivityDetails(yotiOneTimeUseToken)
if len(errStrings) != 0 {
  // handle unhappy path
}
```

### Profile

You can then get the user profile from the activityDetails struct:

```Go
var rememberMeID string = activityDetails.RememberMeID()
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
    //handle error
} else {
    dateOfBirth = dobAttr.Value()
}
var structuredPostalAddress map[string]interface{}
structuredPostalAddressAttribute, err := userProfile.StructuredPostalAddress()
if err != nil {
    //handle error
} else {
    structuredPostalAddress := structuredPostalAddressAttribute.Value().(map[string]interface{})
}
```

If you have chosen Verify Condition on the Yoti Dashboard with the age condition of "Over 18", you can retrieve the user information with the generic .GetAttribute method, which requires the result to be cast to the original type:

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
var value []string = givenNamesFirstAnchor.Value()
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

The `profile` object provides a set of attributes corresponding to user attributes. Whether the attributes are present or not depends on the settings you have applied to your app on Yoti Dashboard.

## Running the Tests

You can run the unit tests for this project by executing the following command inside the repository folder

```Go
go test
```

## AML Integration

Yoti provides an AML (Anti Money Laundering) check service to allow a deeper KYC process to prevent fraud. This is a chargeable service, so please contact [sdksupport@yoti.com](mailto:sdksupport@yoti.com) for more information.

Yoti will provide a boolean result on the following checks:

* PEP list - Verify against Politically Exposed Persons list
* Fraud list - Verify against  US Social Security Administration Fraud (SSN Fraud) list
* Watch list - Verify against watch lists from the Office of Foreign Assets Control

To use this functionality you must ensure your application is assigned to your Organisation in the Yoti Dashboard - please see [here](https://www.yoti.com/developers/documentation/#1-creating-an-organisation) for further information.

For the AML check you will need to provide the following:

* Data provided by Yoti (please ensure you have selected the Given name(s) and Family name attributes from the Data tab in the Yoti Dashboard)
  * Given name(s)
  * Family name
* Data that must be collected from the user:
  * Country of residence (must be an ISO 3166 3-letter code)
  * Social Security Number (US citizens only)
  * Postcode/Zip code (US citizens only)

### Consent

Performing an AML check on a person *requires* their consent.
**You must ensure you have user consent *before* using this service.**

### Code Example

Given a YotiClient initialised with your SDK ID and KeyPair (see [Client Initialisation](#client-initialisation)) performing an AML check is a straightforward case of providing basic profile data.

```Go
givenNames := "Edward Richard George"
familyName := "Heath"

amlAddress := yoti.AmlAddress{
    Country: "GBR"}

amlProfile := yoti.AmlProfile{
    GivenNames: givenNames,
    FamilyName: familyName,
    Address:    amlAddress}

result, err := client.PerformAmlCheck(amlProfile)

log.Printf(
    "AML Result for %s %s:",
    givenNames,
    familyName)
log.Printf(
    "On PEP list: %s",
    strconv.FormatBool(result.OnPEPList))
log.Printf(
    "On Fraud list: %s",
    strconv.FormatBool(result.OnFraudList))
log.Printf(
    "On Watch list: %s",
    strconv.FormatBool(result.OnWatchList))
}
```

Additionally, an [example AML application](/examples/aml/main.go) is provided in the examples folder.

* Rename the [.env.example](examples/profile/.env.example) file to `.env` and fill in the required configuration values (mentioned in the [Configuration](#configuration) section)
* Change directory to the aml example folder: `cd examples/aml`
* Install the dependencies with `go get`
* Start the example with `go run main.go`

## Running the Profile Example

The profile retrieval example can be found in the [examples folder](examples).

* Change directory to the profile example folder: `cd examples/profile`
* On the [Yoti Dashboard](https://www.yoti.com/dashboard/applications):
  * Set the application domain of your app to `localhost:8080`
  * Set the scenario callback URL to `/profile`
* Rename the [.env.example](examples/profile/.env.example) file to `.env` and fill in the required configuration values (mentioned in the [Configuration](#configuration) section)
* Install the dependencies with `go get`
* Start the server with `go run main.go certificatehelper.go`

Visiting `https://localhost:8080/` should show a Yoti Connect button

## API Coverage

* [X] Activity Details
  * [X] Remember Me ID `RememberMeID()`
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
