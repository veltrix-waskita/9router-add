# AWS Builder ID — Captured Endpoint Map

> Captured 2026-07-24T10:19:01.802Z via kiro device-code activation URL
> All secrets redacted: passwords, OTP codes, tokens replaced with `<REDACTED>`

## Summary

- **Total XHR/fetch requests captured:** 72
- **Unique API endpoint groups:** 27
- **Capture duration:** 180s
- **Source:** kiro device-code → AWS Builder ID (IAM Identity Center)
- **User agent:** Chrome (stealth puppeteer)

> **Note:** Redacted fields (`<REDACTED>`) indicate where credentials, tokens, OTP codes, or other secrets were scrubbed from request/response bodies.

---

## Captured Endpoints

Endpoints are grouped by METHOD + pathname. Multiple occurrences of the same endpoint (e.g., redirects or polling) are counted but only the first request/response pair is shown.

### GET `/`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa#/signup/start?workflowID=050d5017-f505-464b-861f-aedabd3d10fa`
- **Occurrences:** 1
- **Content-Type:** text/html

**Request Headers (sample):**
```
referer: https://us-east-1.signin.aws/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
<!doctype html><html lang="en"><head><meta http-equiv="Content-type" content="text/html; charset=utf-8"/><meta name="viewport" content="width=device-width"/><title id="app-title">Amazon Web Services (AWS)</title><link href="/dist/main/app_4c955455c0993a90c164.min.css" rel="stylesheet"></head><body><noscript>You need to enable JavaScript to run this app.</noscript><div id="aws-user-profile-app"></div><script src="/dist/main/app_dc1a861e892db180ecf3.min.js"></script></body></html>
```

---

### GET `/assets/locales/en/createPasswordPage.json`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.<REDACTED>.json`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
:authority: us-east-1.signin.aws
:method: GET
:path: /<REDACTED>.json
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
cookie: <REDACTED>
priority: u=1, i
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/signup?registrationCode=251b8704-5d3c-4358-a466-7d532a23944e&state=<REDACTED>%3D
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{"header":"Choose your password","headerBuilderId":"Create your password","thirdHeading":"Your password provides you with sign in access to AWS access portal, so it's important we get it right.","thirdHeading_aws-cn":"Your password provides you with sign in access to Amazon Web Services access portal, so it's important we get it right.","<REDACTED>":"You will use this password to sign in with your AWS Builder ID.","usernameHeading":"Username: {{username}}","newPasswordInput":"Password","retypePasswordInput":"Confirm password","showPassword":"Show password","matches":"Match","passwordErrorText":"Invalid password","<REDACTED>":"Passwords must match","primaryButtonText":"Set new password","<REDACTED>":"Create AWS Builder ID","<REDACTED>":"Invalid password","<REDACTED>":"Email address has been successfully verified.","<REDACTED>":"You must agree to these terms and conditions to continue.","passwordPlaceholder":"Enter password","<REDACTED>":"Re-enter password"}
```

---

### GET `/assets/locales/en/legalFooter.json`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.<REDACTED>.json`
- **Occurrences:** 2
- **Content-Type:** application/json

**Request Headers (sample):**
```
:authority: us-east-1.signin.aws
:method: GET
:path: /<REDACTED>.json
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
priority: u=1, i
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/login?workflowStateHandle=534db3da-6791-4f13-8306-9ec228be469a
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{"<REDACTED>":"<a href=\"https://aws.amazon.com/agreement/\" target=\"_blank\">AWS Customer Agreement</a>","awsServiceTerms":"<a href=\"https://aws.amazon.com/service-terms/\" target=\"_blank\">AWS Service Terms</a>","siteTerms":"<a href=\"https://aws.amazon.com/terms/\" target=\"_blank\">Site Terms</a>","<REDACTED>":"<a href=\"https://aws.amazon.com/aup/\" target=\"_blank\">AWS Acceptable Use Policy</a>","awsCookieNotice":"<a href=\"https://aws.amazon.com/legal/cookies/\" target=\"_blank\">AWS Cookie Notice</a>","awsPrivacyNotice":"<a href=\"https://aws.amazon.com/privacy/\" target=\"_blank\">AWS Privacy Notice</a>","awsCopyright":"© {{year}}, Amazon Web Services, Inc. or its affiliates. All rights reserved.","<REDACTED>":"Cookie Preferences","builderId":{"siteTerms":"Site terms","privacy":"Privacy","<REDACTED>":"Cookie preferences","awsCopyright":"© {{year}}, Amazon Web Services, Inc. or its affiliates. All rights reserved."}}
```

---

### GET `/assets/locales/en/passwordPolicy.json`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.<REDACTED>.json`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
:authority: us-east-1.signin.aws
:method: GET
:path: /<REDACTED>.json
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
cookie: <REDACTED>
priority: u=1, i
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/signup?registrationCode=251b8704-5d3c-4358-a466-7d532a23944e&state=<REDACTED>%3D
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{"use":"Use:","characterCount":"Must be between {{min}}-{{max}} characters","characterCasing":"Use upper and lower case letters","specificCharacters":"Specified characters {{charSet}}","nonAlphaNumeric":"Use a symbol","numbers":"Use a number","strong":"Strong","weak":"Weak"}
```

---

### GET `/assets/locales/en/usernamePage.json`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.<REDACTED>.json`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
:authority: us-east-1.signin.aws
:method: GET
:path: /<REDACTED>.json
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
cookie: <REDACTED>
priority: u=1, i
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/login?workflowStateHandle=534db3da-6791-4f13-8306-9ec228be469a
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{"header":"Sign in","sonoHeader":"Sign in with AWS Builder ID","sonoSubHeader":"With AWS Builder ID","sonoSignupHeader":"Create AWS Builder ID","createYourBuilderId":"Create your AWS Builder ID","headerAlias":"Sign in to","usernameText":"Username","emailText":"Your email address","builderIdEmailLabel":"Email","usernameErrorText":"Invalid username","emailErrorText":"Invalid email","inputPlaceHolder":"Your company username","rememberUsername":"Remember username","rememberEmail":"Save my email address","signUp":"Create your AWS Builder ID","signUpHeader":"Create","signUpSubHeader":"With a personal email address","signInSubHeader":"With your personal email address","signIn":"Already have AWS Builder ID? Sign in","<REDACTED>":"Already have AWS Builder ID?","notRegistered":"Not registered?","gdprCookieNotice":"By continuing, you agree to the <a href=\"https://aws.amazon.com/agreement/\" target=\"_blank\">AWS Customer Agreement</a> or other agreement for AWS services, and the <a href=\"https://aws.amazon.com/privacy/\" target=\"_blank\">Privacy Notice</a>. This site uses essential cookies. See our <a href=\"https://aws.amazon.com/legal/cookies\" target=\"_blank\">Cookie Notice</a> for more information.","gdprCookieNotice_aws-cn_bjs":"By continuing, you agree to the <a href=\"https://www.amazonaws.<REDACTED>/\" target=\"_blank\">Sinnet Customer Agreement for Amazon Web Services (Beijing Region)</a> or other agreement governing your use of Amazon Web Services services, and the <a href=\"https://www.amazonaws.<REDACTED>\" target=\"_blank\">Sinnet Privacy Policy for Amazon Web Services (Beijing Region)</a>. This site uses essential cookies. See our <a href=\"https://www.amazonaws.<REDACTED>/\" target=\"_blank\">Cookie Notice</a> for more information.","gdprCookieNotice_aws-cn_zhy":"By continuing, you agree to the <a href=\"https://www.amazonaws.<REDACTED>/\" target=\"_blank\">Western Cloud Data Customer Agreement for Amazon Web Services (Ningxia Region)</a> or other agreement governing your use of Amazon Web Services services, and the  <a href=\"https://www.amazonaws.<REDACTED>\" target=\"_blank\">Western Cloud Data Privacy Policy for Amazon Web Services (Ningxia Region)</a>. This site uses essential cookies. See our <a href=\"https://www.amazonaws.<REDACTED>/\" target=\"_blank\">Cookie Notice for more information.</a>","<REDACTED>":"By continuing and using an AWS Builder ID, you agree to the <a href=\"https://aws.amazon.com/agreement/\" target=\"_blank\">AWS Customer Agreement</a> (\"Agreement\"), <a href=\"https://aws.amazon.com/service-terms/\" target=\"_blank\">AWS Service Terms</a>, <a href=\"https://aws.amazon.com/privacy/\" target=\"_blank\">AWS Privacy Notice</a>, and <a href=\"https://aws.amazon.com/aup/\" target=\"_blank\">AWS Acceptable Use Policy</a>. Your AWS Builder ID is considered an AWS account for the purposes of the Agreement. This site uses essential cookies. See our <a href=\"https://aws.amazon.com/legal/cookies\" target=\"_blank\">Cookie Notice</a> for more information.","builderIdPolicy":"By clicking \"Continue\" or continuing with an alternative sign-in method, you agree to the <<REDACTED>>AWS Customer Agreement</<REDACTED>>, and you acknowledge you have read the <awsPrivacyNotice>AWS Privacy Notice</awsPrivacyNotice>. By continuing, you will create an <awsBuilderId>AWS Builder ID</awsBuilderId>.","<REDACTED>":"the application","<REDACTED>":"AWS Builder ID is a new personal profile for builders.","smartcard":"Sign in with smart card","sonoDescription1":"Get started for free","sonoDescription2":"Complement your existing AWS accounts","sonoDescription3":"Secure your login with optional MFA","continueWith":"Continue with ","signUpWith":"Sign up with ","signInWith":"Continue with {{appName}}","<REDACTED>":"AWS Builder ID is your personal","builderProfile":"builder profile.","newToAwsBuilderId":"New to AWS Builder ID?","createYourProfile":"Create your profile.","withOtherOptions":"With other options","youWillBeRedirected":"You will be redirected to complete sign in.","freeToGetStarted":"FREE to get started","<REDACTED>":"AWS Builder ID complements any AWS accounts you may already own or want to create. It represents you as an individual and is independent from any credentials and data you may have in existing AWS accounts.","<REDACTED>":"Username","<REDACTED>":"Username (not email address)","<REDACTED>":"Get started","<REDACTED>":"username@example.com","troubleRecoveryText":"Trouble Signing In?"}
```

---

### GET `/dist/locales/en-US_5bbe19f56bb47a0809c324b77927d292.json`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.com/dist/locales/en-US_5bbe19f56bb47a0809c324b77927d292.json`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
referer: https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{
    "Profile": {
        "Heading": {
            "text": "Profile",
            "note": "Heading for Profile page"
        },
        "My_Details": {
            "text": "My details",
            "note": "Label for user profile details title"
        },
        "My_Details_Description": {
            "text": "Changes to your AWS Builder ID apply to all AWS services and applications that you access using your AWS Builder ID.",
            "note": "Description for the My details page"
        },
        "Profile_Information": {
            "text": "Profile information",
            "note": "Heading for Profile Information component"
        },
        "Edit_Profile": {
            "text": "Edit profile",
            "note": "Text for Edit Profile page for breadcrumb and header"
        },
        "Edit_Profile_Description": {
            "text": "Changes you make here will apply to all AWS applications you use with this AWS Builder ID.",
            "note": "Edit Profile description"
        },
        "Contact_Information": {
            "text": "Contact information",
            "note": "Heading for Contact Information component"
        },
        "Edit_Contact_Information": {
            "text": "Edit contact information",
            "note": "Text for Edit Contact Information page for breadcrumb and header"
        },
        "Edit_Button_Text": {
            "text": "Edit",
            "note": "Text for profile edit button"
        },
        "Change_Password_Button_Text": {
            "text": "Change password",
            "note": "Text for change password button"
        },
        "Cancel_Button_Text": {
            "text": "Cancel",
            "note": "Text for cancel button"
        },
        "Save_Changes_Button_Text": {
            "text": "Save changes",
            "note": "Text for save changes button"
        },
        "Verify_Email_Button_Text": {
            "text": "Verify email",
            "note": "Text for verify email button"
        },
        "Full_Name_Label": {
            "text": "Full name",
            "note": "Label for Full name in user profile"
        },
        "Name_Label": {
            "text": "Name",
            "note": "Label for name in user profile"
        },
        "Name_Desc": {
            "text": "This might be visible to other people using AWS.",
            "note": "Description for name in user profile"
        },
        "Full_Name_Desc": {
            "text": "Full name is how you will be referred to in applications when collaborating with others.",
            "note": "Description for Full name in user profile"
        },
        "Full_Name_Info": {
            "text": "Full name is how you will be referred to in applications where your real name is expected.",
            "note": "Information shown for Full name as tooltip"
        },
        "Full_Name_Info_Example": {
            "text": "Example: Ana Carolina Silva",
            "note": "Example shown in italics in Full name tooltip"
        },
        "Nick_Name_Label": {
            "text": "Nickname",
            "note": "Label for Nickname in user profile"
        },
        "Nick_Name_Desc": {
            "text": "Nickname is how you would like to be called by AWS, friends and people with whom you work closely.",
            "note": "Description for Nickname in user profile"
        },
        "Nick_Name_Info": {
            "text": "Nickname is what you prefer to be called by AWS, friends, and people with whom you work closely.",
            "note": "Information shown for Nickname as tooltip"
        },
        "Nick_Name_Info_Example": {
            "text": "Example: Anita",
            "note": "Example shown in italics in Nickname tooltip"
        },
        "Alias_Label": {
            "text": "Alias",
            "note": "Label for Alias in user profile"
        },
        "Alias_Desc": {
            "text": "Alias is a unique value visible to others in public comment streams, for @mentioning in applications, etc.",
            "note": "Description for Alias in user profile"
        },
        "Alias_Constraint_Text": {
            "text": "Must be at least 3 characters. Has to be unique from all other AWS ID users. Only alphanumeric characters are allowed.",
            "note": "Constraint Text for Alias in user profile edit page"
        },
        "Alias_Info": {
            "text": "Alias is a unique value visible to others in public comment streams, for @mentioning in applications, etc.",
            "note": "Information shown for Alias as tooltip"
        },
        "Alias_Info_Example": {
            "text": "Example: codeninja99",
            "note": "Example shown in italics in Alias tooltip"
        },
        "Address_City_Label": {
            "text": "City",
            "note": "Label for city of the address in user profile"
        },
        "Address_Country_Label": {
            "text": "Country",
            "note": "Label for country of the address in user profile"
 
```

---

### GET `/dist/locales/nav-en-US_254d2e9f8362a2975ed05b6e14fc7a38.json`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.<REDACTED>-en-US_254d2e9f8362a2975ed05b6e14fc7a38.json`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
referer: https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{
    "LegalFooterLink": {
        "Privacy": {
            "text": "Privacy",
            "note": "Legal Footer Privacy link"
        },
        "Terms": {
            "text": "Terms",
            "note": "Legal Footer Terms Link"
        },
        "Cookie_Preferences": {
            "text": "Cookie preferences",
            "note": "Cookie Preferences link"
        },
        "<REDACTED>": {
            "text": "© {{year}}, Amazon Web Services, Inc. or its affiliates. All rights reserved.",
            "note": "Copy Right Link"
        }
    },
    "NavigationHeader": {
        "FieldSeparator": {
            "text": "|",
            "note": "Feild Sepeeator"
        },
        "AWS_Alt_Logo": {
            "text": "AWS",
            "note": "AWS Alt text"
        },
        "LogoutButtonText": {
            "text": "Sign out",
            "note": "Sign out button Text"
        }
    },
    "ProfileNavigation": {
        "Home": {
            "text": "AWS Builder ID",
            "note": "AWS Builder ID home button"
        },
        "My_Details": {
            "text": "My details",
            "note": "My Details Side Nav Link"
        },
        "Security": {
            "text": "Security",
            "note": "Security Side Nav Link"
        },
        "Privacy_And_Data": {
            "text": "Privacy & data",
            "note": "Privacy & data side Nav link"
        }
    }
}

```

---

### GET `/login`

- **Host:** `portal.sso.us-east-1.amazonaws.com`
- **Full URL:** `https://portal.sso.us-east-1.amazonaws.com/login?directory_id=view&redirect_url=https%3A%2F%2Fview.awsapps.com%2Fstart%2F%23%2Fdevice%3Fuser_code%3DCQXT-CZKW`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
content-type: application/json
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{"redirectUrl":"https://us-east-1.signin.aws/platform/d-9067642ac7/login?workflowStateHandle=534db3da-6791-4f13-8306-9ec228be469a","csrfToken":"912061796"}
```

---

### GET `/platform/d-9067642ac7/signup`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.aws/platform/d-9067642ac7/signup?registrationCode=251b8704-5d3c-4358-a466-7d532a23944e&state=<REDACTED>%3D`
- **Occurrences:** 1
- **Content-Type:** text/html;charset=UTF-8

**Request Headers (sample):**
```
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta
      name="viewport"
    />

    <!-- Prefetch likely needed resources -->
    <link rel="preload" href="/platform/config?directoryId=" as="fetch" crossorigin="anonymous" referrerpolicy="same-origin" />
    <link rel="preload" as="fetch" crossorigin="anonymous" referrerpolicy="same-origin" href="/<REDACTED>.json" />
    <link rel="preload" as="fetch" crossorigin="anonymous" referrerpolicy="same-origin" href="/<REDACTED>.json" />
    <link rel="preload" as="fetch" crossorigin="anonymous" referrerpolicy="same-origin" href="/<REDACTED>.json" />
    <link rel="preload" as="fetch" crossorigin="anonymous" referrerpolicy="same-origin" href="/<REDACTED>.json" />
    <link rel="preload" as="fetch" crossorigin="anonymous" referrerpolicy="same-origin" href="/<REDACTED>.json" />

    <!-- DNS prefetch for external domains -->
    <link rel="dns-prefetch" href="//d35uxhjf90umnp.cloudfront.net" />
    <link rel="dns-prefetch" href="//prod.assets.shortbread.aws.dev" />
    <link rel="dns-prefetch" href="//prod.log.shortbread.aws.dev" />

    <title>Amazon Web Services</title>
  <link rel="shortcut icon" href="/favicon.ico"><link href="/assets/css/app.css" rel="stylesheet"></head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="main-container" class="awsui"></div>
  <script type="text/javascript" src="/assets/js/app.js"></script></body>
</html>


```

---

### GET `/token/whoAmI`

- **Host:** `portal.sso.us-east-1.amazonaws.com`
- **Full URL:** `https://portal.sso.us-east-1.amazonaws.com/token/whoAmI`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
authorization: <REDACTED>
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Response:** HTTP 200
```
{"userIdentifier":"<REDACTED>=","token":null,"createDate":1784888227000,"tokenType":"NATIVE","expireDate":1787480224000,"accountId":"432677196278","directoryId":"d-9067642ac7","authenticationType":"NATIVE","identityStoreUserId":"d4480488-b031-7048-4094-f217adb8544c","originSessionId":"042894f8-6091-706a-633b-910f391c3af8","<REDACTED>":null}
```

---

### POST `/api/create-identity`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.com/api/create-identity`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
:authority: profile.aws.amazon.com
:method: POST
:path: /api/create-identity
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
content-length: 6970
content-type: application/json;charset=UTF-8
cookie: <REDACTED>
origin: https://profile.aws.amazon.com
priority: u=1, i
referer: https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"workflowState":"251b8704-5d3c-4358-a466-7d532a23944e","userData":{"email":"<REDACTED_EMAIL>","fullName":"<REDACTED_NAME>"},"otpCode":"685525","browserData":{"attributes":{"fingerprint":"ECdITeCs:<REDACTED>=","eventTimestamp":"2026-07-24T10:16:42.103Z","timeSpentOnPage":"13033","pageName":"EMAIL_VERIFICATION","eventType":"EmailVerification","ubid":"485-8321923-7639224"},"cookies":{}}}
```

**Response:** HTTP 200
```
{"registrationCode":"251b8704-5d3c-4358-a466-7d532a23944e","signInState":"<REDACTED>="}
```

---

### POST `/api/get-app-context`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.com/api/get-app-context`
- **Occurrences:** 1

**Request Headers (sample):**
```
:authority: profile.aws.amazon.com
:method: POST
:path: /api/get-app-context
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
content-length: 53
content-type: application/json;charset=UTF-8
cookie: <REDACTED>
origin: https://profile.aws.amazon.com
priority: u=1, i
referer: https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"workflowID":"050d5017-f505-464b-861f-aedabd3d10fa"}
```

---

### POST `/api/get-config`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.com/api/get-config`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
:authority: profile.aws.amazon.com
:method: POST
:path: /api/get-config
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
content-length: 2
content-type: application/json;charset=UTF-8
cookie: <REDACTED>
origin: https://profile.aws.amazon.com
priority: u=1, i
referer: https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{}
```

**Response:** HTTP 200
```
{"features":{"AddressCollection":{"featureVariation":"DISABLED"},"UserAlias":{"featureVariation":"DISABLED"}}}
```

---

### POST `/api/send-otp`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.com/api/send-otp`
- **Occurrences:** 1

**Request Headers (sample):**
```
:authority: profile.aws.amazon.com
:method: POST
:path: /api/send-otp
:scheme: https
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
content-length: 6891
content-type: application/json;charset=UTF-8
cookie: <REDACTED>
origin: https://profile.aws.amazon.com
priority: u=1, i
referer: https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"workflowState":"251b8704-5d3c-4358-a466-7d532a23944e","email":"<REDACTED_EMAIL>","browserData":{"attributes":{"fingerprint":"ECdITeCs:<REDACTED>","eventTimestamp":"2026-07-24T10:16:27.434Z","timeSpentOnPage":"7031","pageName":"EMAIL_COLLECTION","eventType":"PageSubmit","ubid":"485-8321923-7639224"},"cookies":{}}}
```

---

### POST `/api/start`

- **Host:** `profile.aws.amazon.com`
- **Full URL:** `https://profile.aws.amazon.com/api/start`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
content-type: application/json;charset=UTF-8
referer: https://profile.aws.amazon.com/?workflowID=050d5017-f505-464b-861f-aedabd3d10fa
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"workflowID":"050d5017-f505-464b-861f-aedabd3d10fa","browserData":{"attributes":{"fingerprint":"ECdITeCs:<REDACTED>==","eventTimestamp":"2026-07-24T10:16:19.722Z","timeSpentOnPage":"134","eventType":"PageLoad","ubid":"485-8321923-7639224"},"cookies":{}}}
```

**Response:** HTTP 200
```
{"email":"<REDACTED_EMAIL>","<REDACTED>":"https://us-east-1.signin.aws/platform/d-9067642ac7/signup","redirectUrl":"https://us-east-1.signin.aws/platform/d-9067642ac7/login?workflowStateHandle=534db3da-6791-4f13-8306-9ec228be469a","workflowState":"251b8704-5d3c-4358-a466-7d532a23944e"}
```

---

### POST `/auth/sso-token`

- **Host:** `portal.sso.us-east-1.amazonaws.com`
- **Full URL:** `https://portal.sso.us-east-1.amazonaws.com/auth/sso-token`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
content-type: application/x-www-form-urlencoded
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
x-amz-sso-csrf-token: 912061796
```

**Request Body (redacted):**
```
authCode=e0a9ccc5-9e3c-4c4f-959a-b723c86c2405&state=<REDACTED>%3D%3D&orgId=view
```

**Response:** HTTP 200
```
{"token":"<REDACTED>.<REDACTED>-5do8HhSK9WbhM3dIiMuf4AnvV_jvDR8XjWvcnO9aAT_xrZ3d5spgm57jHTyCxPkAAAB-MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzf8AWs5FNKMuquf4YCARCAO_nmQfC74E7YXwSZ-YcidMlCLkJz0PLguJqv2aAOyckUeqoETx5shbBDb7hKREkN853_SR9GNkbWgrS1AgAAAAAMAAAQAAAAAAAAAAAAAAAAAOD5SecZsPqwO8LmROFuaQb_____AAAAAQAAAAAAAAAAAAAAAQAAACDt813rcIbDPUQybRgjL9SoOTjKJbPwUtYp7lH6UnRh0iIDn1RlQb2oDXgVYlH7Y2o.KuIj3X-jztqbRgCd.-IcxdvB6yVfDeNI4SX2M-owjFg0QHGI7BRLxnjV9FcVmYW6mr65b4TZaMTgwkyRtCsRV5O_-<REDACTED>-CiP-EwA-Mic8wRYj1ubOR_Kr6-HKRCIbguVlCgEL-qtPkiyZV3iJs5evoBK_dIblmGE0wpxNWHQ1DWEvK6qxfO5GQsl0bODK7_5cY3xWLQxoXTZwEaNvIJ3mXlW8uYakQWDnBGpTzaYys_7mlc-<REDACTED>-cNs65ha6P3RiBLGEysAv6qfk1X1pWDeBD5FQcjuGiju9hWI1zU3dKsQi06DtiRZUjaKSbi31a8PTNQmf_CVOxYkSjizcE50QSyFD26ys8Te_k8RgahzXi0yRMIdVuugaNHFD5vyYIrKIVhZKCUW-kV-2Gffh4gQpj4HcREZuOo5uJccqsPYb0JQLXWVA4tOXxdPcC_lw-<REDACTED>.EigDfVfcoz7rS-8fTyE5dQ","redirectUrl":"https://view.awsapps.com/start/#/device?user_code=CQXT-CZKW","errorMessage":null,"relayId":null,"initType":"SAML_IDP"}
```

---

### POST `/consent_details`

- **Host:** `oidc.us-east-1.amazonaws.com`
- **Full URL:** `https://oidc.us-east-1.amazonaws.com/consent_details`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
content-type: application/json
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"deviceContextId":"<REDACTED>.<REDACTED>.<REDACTED>-bju9c_xSzmJKKg2hPMb8RfQYejHn-","clientId":"0o3EowjdaDUHB9N0ZH-OInVzLWVhc3QtMQ","clientType":"public","userSessionId":"<REDACTED>.<REDACTED>-5do8HhSK9WbhM3dIiMuf4AnvV_jvDR8XjWvcnO9aAT_xrZ3d5spgm57jHTyCxPkAAAB-MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzf8AWs5FNKMuquf4YCARCAO_nmQfC74E7YXwSZ-YcidMlCLkJz0PLguJqv2aAOyckUeqoETx5shbBDb7hKREkN853_SR9GNkbWgrS1AgAAAAAMAAAQAAAAAAAAAAAAAAAAAOD5SecZsPqwO8LmROFuaQb_____AAAAAQAAAAAAAAAAAAAAAQAAACDt813rcIbDPUQybRgjL9SoOTjKJbPwUtYp7lH6UnRh0iIDn1RlQb2oDXgVYlH7Y2o.KuIj3X-jztqbRgCd.-IcxdvB6yVfDeNI4SX2M-owjFg0QHGI7BRLxnjV9FcVmYW6mr65b4TZaMTgwkyRtCsRV5O_-<REDACTED>-CiP-EwA-Mic8wRYj1ubOR_Kr6-HKRCIbguVlCgEL-qtPkiyZV3iJs5evoBK_dIblmGE0wpxNWHQ1DWEvK6qxfO5GQsl0bODK7_5cY3xWLQxoXTZwEaNvIJ3mXlW8uYakQWDnBGpTzaYys_7mlc-<REDACTED>-cNs65ha6P3RiBLGEysAv6qfk1X1pWDeBD5FQcjuGiju9hWI1zU3dKsQi06DtiRZUjaKSbi31a8PTNQmf_CVOxYkSjizcE50QSyFD26ys8Te_k8RgahzXi0yRMIdVuugaNHFD5vyYIrKIVhZKCUW-kV-2Gffh4gQpj4HcREZuOo5uJccqsPYb0JQLXWVA4tOXxdPcC_lw-<REDACTED>.EigDfVfcoz7rS-8fTyE5dQ"}
```

**Response:** HTTP 200
```
{"clientName":"kiro-oauth-client","consentDetails":[{"applicationName":"Kiro","descriptions":[{"detailedTitle":"Details on analysis","longDescription":"Enable security scans with suggestions to help remediate issues.","resourceType":"analysis","shortDescription":"Enable access to Kiro code analysis."},{"detailedTitle":"Details on completions","longDescription":"Enable inline code suggestions based on existing code and comments.","resourceType":"completions","shortDescription":"Enable access to Kiro inline code suggestions."},{"detailedTitle":"Details on conversations","longDescription":"Enable users to ask software development questions, request explanations for their code, etc. via chat.","resourceType":"conversations","shortDescription":"Enable access to Kiro chat."}]}],"consentStatus":"PENDING","nextToken":null}
```

---

### POST `/csds/collector/v1/events/batch`

- **Host:** `d2c.aws.amazon.com`
- **Full URL:** `https://d2c.aws.amazon.<REDACTED>`
- **Occurrences:** 1
- **Content-Type:** text/xml

**Request Headers (sample):**
```
accept: application/json
content-type: application/json
referer: https://us-east-1.signin.aws/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"batchId":"D2CLogger","schemaVersion":"1.0.0","batchEvents":[{"pageURL":"https://us-east-1.signin.aws/platform/d-9067642ac7/login?workflowStateHandle=534db3da-6791-4f13-8306-9ec228be469a","eventType":"logEvent","eventTimestamp":1784888164369,"customData":{"timeTakenToFetchVID":"939","logLevel":"info"},"orgId":"awsme_scode"}]}
```

**Response:** HTTP 202
```
<unreadable>
```

---

### POST `/device_authorization/accept_user_code`

- **Host:** `oidc.us-east-1.amazonaws.com`
- **Full URL:** `https://oidc.us-east-1.amazonaws.com/device_authorization/accept_user_code`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
content-type: application/json
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"userCode":"CQXT-CZKW","userSessionId":"<REDACTED>.<REDACTED>-5do8HhSK9WbhM3dIiMuf4AnvV_jvDR8XjWvcnO9aAT_xrZ3d5spgm57jHTyCxPkAAAB-MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzf8AWs5FNKMuquf4YCARCAO_nmQfC74E7YXwSZ-YcidMlCLkJz0PLguJqv2aAOyckUeqoETx5shbBDb7hKREkN853_SR9GNkbWgrS1AgAAAAAMAAAQAAAAAAAAAAAAAAAAAOD5SecZsPqwO8LmROFuaQb_____AAAAAQAAAAAAAAAAAAAAAQAAACDt813rcIbDPUQybRgjL9SoOTjKJbPwUtYp7lH6UnRh0iIDn1RlQb2oDXgVYlH7Y2o.KuIj3X-jztqbRgCd.-IcxdvB6yVfDeNI4SX2M-owjFg0QHGI7BRLxnjV9FcVmYW6mr65b4TZaMTgwkyRtCsRV5O_-<REDACTED>-CiP-EwA-Mic8wRYj1ubOR_Kr6-HKRCIbguVlCgEL-qtPkiyZV3iJs5evoBK_dIblmGE0wpxNWHQ1DWEvK6qxfO5GQsl0bODK7_5cY3xWLQxoXTZwEaNvIJ3mXlW8uYakQWDnBGpTzaYys_7mlc-<REDACTED>-cNs65ha6P3RiBLGEysAv6qfk1X1pWDeBD5FQcjuGiju9hWI1zU3dKsQi06DtiRZUjaKSbi31a8PTNQmf_CVOxYkSjizcE50QSyFD26ys8Te_k8RgahzXi0yRMIdVuugaNHFD5vyYIrKIVhZKCUW-kV-2Gffh4gQpj4HcREZuOo5uJccqsPYb0JQLXWVA4tOXxdPcC_lw-<REDACTED>.EigDfVfcoz7rS-8fTyE5dQ"}
```

**Response:** HTTP 200
```
{"deviceContext":{"clientId":"0o3EowjdaDUHB9N0ZH-OInVzLWVhc3QtMQ","clientType":"public","deviceContextId":"<REDACTED>.<REDACTED>.<REDACTED>-bju9c_xSzmJKKg2hPMb8RfQYejHn-"},"hasConsentDetails":true}
```

---

### POST `/device_authorization/associate_token`

- **Host:** `oidc.us-east-1.amazonaws.com`
- **Full URL:** `https://oidc.us-east-1.amazonaws.com/device_authorization/associate_token`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
content-type: application/json
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"deviceContext":{"deviceContextId":"<REDACTED>.<REDACTED>.<REDACTED>-bju9c_xSzmJKKg2hPMb8RfQYejHn-","clientId":"0o3EowjdaDUHB9N0ZH-OInVzLWVhc3QtMQ","clientType":"public"},"userSessionId":"<REDACTED>.<REDACTED>-5do8HhSK9WbhM3dIiMuf4AnvV_jvDR8XjWvcnO9aAT_xrZ3d5spgm57jHTyCxPkAAAB-MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzf8AWs5FNKMuquf4YCARCAO_nmQfC74E7YXwSZ-YcidMlCLkJz0PLguJqv2aAOyckUeqoETx5shbBDb7hKREkN853_SR9GNkbWgrS1AgAAAAAMAAAQAAAAAAAAAAAAAAAAAOD5SecZsPqwO8LmROFuaQb_____AAAAAQAAAAAAAAAAAAAAAQAAACDt813rcIbDPUQybRgjL9SoOTjKJbPwUtYp7lH6UnRh0iIDn1RlQb2oDXgVYlH7Y2o.KuIj3X-jztqbRgCd.-IcxdvB6yVfDeNI4SX2M-owjFg0QHGI7BRLxnjV9FcVmYW6mr65b4TZaMTgwkyRtCsRV5O_-<REDACTED>-CiP-EwA-Mic8wRYj1ubOR_Kr6-HKRCIbguVlCgEL-qtPkiyZV3iJs5evoBK_dIblmGE0wpxNWHQ1DWEvK6qxfO5GQsl0bODK7_5cY3xWLQxoXTZwEaNvIJ3mXlW8uYakQWDnBGpTzaYys_7mlc-<REDACTED>-cNs65ha6P3RiBLGEysAv6qfk1X1pWDeBD5FQcjuGiju9hWI1zU3dKsQi06DtiRZUjaKSbi31a8PTNQmf_CVOxYkSjizcE50QSyFD26ys8Te_k8RgahzXi0yRMIdVuugaNHFD5vyYIrKIVhZKCUW-kV-2Gffh4gQpj4HcREZuOo5uJccqsPYb0JQLXWVA4tOXxdPcC_lw-<REDACTED>.EigDfVfcoz7rS-8fTyE5dQ"}
```

**Response:** HTTP 200
```
{"location":null}
```

---

### POST `/log`

- **Host:** `log.sso-portal.us-east-1.amazonaws.com`
- **Full URL:** `https://log.sso-portal.us-east-1.amazonaws.com/log`
- **Occurrences:** 3
- **Content-Type:** application/json

**Request Headers (sample):**
```
accept: application/json, text/plain
content-type: application/json
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"type":"inline","entry":{"region":"us-east-1","url":"https://view.awsapps.com/start/#/device?user_code=CQXT-CZKW","message":"whoAmI:200","error":"","timestamp":"2026-07-24T10:15:52.649Z"}}
```

**Response:** HTTP 200
```
<unreadable>
```

---

### POST `/metrics/fingerprint`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.<REDACTED>`
- **Occurrences:** 3

**Request Headers (sample):**
```
:authority: us-east-1.signin.aws
:method: POST
:path: /metrics/fingerprint
:scheme: https
accept: application/json, text/plain, */*
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
content-length: 6064
content-type: application/x-www-form-urlencoded;charset=UTF-8
origin: https://us-east-1.signin.aws
priority: u=1, i
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/login?workflowStateHandle=534db3da-6791-4f13-8306-9ec228be469a
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-origin
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
name=<REDACTED>:Success&value=ECdITeCs:<REDACTED>&operation=AWSSignin:FingerprintMetrics:start
```

**Response:** HTTP 200

---

### POST `/panoramaroute`

- **Host:** `us-east-1.prod.pl.panorama.console.api.aws`
- **Full URL:** `https://us-east-1.prod.pl.panorama.console.api.aws/panoramaroute`
- **Occurrences:** 8
- **Content-Type:** application/json

**Request Headers (sample):**
```
content-type: application/json; charset=UTF-8
panorama-appentity: aws-idc-access-portal
referer: https://view.awsapps.com/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{"consoleService":"aws-idc-access-portal","consoleRegion":"us-east-1","awsUserInfo":"","awsUserInfoSigned":"","appEntity":"aws-idc-access-portal","visitorInfo":"","version":"2.8.228","tabId":"e0dfe4cb-e2df-4755-a3d4-434757903401","modality":"web","deviceTimeZone":"-420","browserLanguage":"en-US","<REDACTED>":"1920","<REDACTED>":"1080","browserColorDepth":"24","domain":"NonProd","browserCookies":"","awsIdentityToken":"","batchRequest":[{"eventType":"panoramaPing","eventContext":"pageload","eventDetail":"","eventValue":"1","timestamp":1784888153014,"eventSource":"panorama","requestId":"0bb2d4fd-b7c1-4ed7-ab7f-40377f179b87","service":"aws-idc-access-portal","consoleRegion":"us-east-1","version":"2.8.228","tabId":"e0dfe4cb-e2df-4755-a3d4-434757903401","modality":"web","deviceTimeZone":"-420","browserLanguage":"en-US","<REDACTED>":"1920","<REDACTED>":"1080","browserColorDepth":"24","domain":"NonProd","browserCookies":"","<REDACTED>":958,"<REDACTED>":913,"referrer":"","requestUri":"https://view.awsapps.com/start/#/device?user_code=CQXT-CZKW","pageUrlPath":"https://view.awsapps.com/start/#/device?user_code=CQXT-CZKW"}],"batchRequestId":"0baf2e79-c8fd-4505-9456-5bbf78761afb"}
```

**Response:** HTTP 200
```
{"batchRequestId":"a124c844-074a-40fb-bd4e-f3326e7c6262","status":"SUCCESS"}
```

---

### POST `/platform/d-9067642ac7/api/execute`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.aws/platform/d-<REDACTED>`
- **Occurrences:** 5
- **Content-Type:** application/json;charset=UTF-8

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
content-type: application/json; charset=UTF-8
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/login?workflowStateHandle=534db3da-6791-4f13-8306-9ec228be469a
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
x-amz-date: Fri, 24 Jul 2026 10:15:58 GMT
x-amzn-requestid: a64e2e9f-a607-4899-81ea-44285f925c0e
```

**Request Body (redacted):**
```
{"stepId":"","workflowStateHandle":"534db3da-6791-4f13-8306-9ec228be469a","inputs":[{"input_type":"<REDACTED>","fingerPrint":"ECdITeCs:<REDACTED>=="}],"requestId":"a64e2e9f-a607-4899-81ea-44285f925c0e"}
```

**Response:** HTTP 200
```
{"requestId":"a5dc6d3e-1610-44c6-ae2f-4cb44c8a1ecb","workflowStateHandle":"f67d9ffb-3aaa-4841-8d31-477a17739c1f","stepId":"start","presentationContext":{"clientId":"3bec6266d4c83882","identityPoolId":"d-9067642ac7","identityPoolType":"DIRECTORY","identityPoolAlias":"view","applicationType":"SSO_INDIVIDUAL_ID","arnPartition":"aws","locale":"","airportCode":"IAD"},"<REDACTED>":{}}
```

---

### POST `/platform/d-9067642ac7/signup/api/execute`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.aws/platform/d-<REDACTED>`
- **Occurrences:** 4
- **Content-Type:** application/json;charset=UTF-8

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
content-type: application/json; charset=UTF-8
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/signup?workflowStateHandle=3f9de370-4a05-4b92-93a7-3a2e1ca47299
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
x-amz-date: Fri, 24 Jul 2026 10:16:05 GMT
x-amzn-requestid: a108905c-1e41-4107-babe-52bfc69527d2
```

**Request Body (redacted):**
```
{"stepId":"","workflowStateHandle":"3f9de370-4a05-4b92-93a7-3a2e1ca47299","inputs":[{"input_type":"UserRequestInput","username":"<REDACTED_EMAIL>"},{"input_type":"<REDACTED>","fingerPrint":"ECdITeCs:<REDACTED>"}],"visitorId":"0ecfc9cf-fff2-11c2-0cfb-446530ace0be","requestId":"a108905c-1e41-4107-babe-52bfc69527d2"}
```

**Response:** HTTP 200
```
{"requestId":"6947e353-0fd0-4ff4-a6b0-1ffae6425d42","workflowStateHandle":"47c16efb-85d7-41e5-9e3f-53a000e657aa","stepId":"start","presentationContext":{"clientId":"3bec6266d4c83882","identityPoolId":"d-9067642ac7","username":"<REDACTED_EMAIL>","identityPoolType":"DIRECTORY","applicationType":"SSO_INDIVIDUAL_ID","arnPartition":"aws","locale":"","airportCode":"IAD"}}
```

---

### POST `/platform/user-event/send-event`

- **Host:** `us-east-1.signin.aws`
- **Full URL:** `https://us-east-1.signin.aws/platform/user-event/send-event`
- **Occurrences:** 1
- **Content-Type:** application/json;charset=UTF-8

**Request Headers (sample):**
```
accept: application/json, text/plain, */*
content-type: application/json; charset=UTF-8
referer: https://us-east-1.signin.aws/platform/d-9067642ac7/signup?registrationCode=251b8704-5d3c-4358-a466-7d532a23944e&state=<REDACTED>%3D
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
x-amz-date: Fri, 24 Jul 2026 10:16:49 GMT
x-amzn-requestid: 40417adf-46ce-4ac9-8f16-9aa34fd41c96
```

**Request Body (redacted):**
```
{"inputs":[{"input_type":"<REDACTED>","directoryId":"d-9067642ac7","userName":"<REDACTED_EMAIL>","userEvents":[{"input_type":"UserEvent","eventType":"PAGE_LOAD","pageName":"CREDENTIAL_COLLECTION"}]},{"input_type":"<REDACTED>","fingerPrint":"ECdITeCs:/<REDACTED>"}],"requestId":"40417adf-46ce-4ac9-8f16-9aa34fd41c96"}
```

**Response:** HTTP 200

---

### POST `/token`

- **Host:** `vs.aws.amazon.com`
- **Full URL:** `https://vs.aws.amazon.com/token`
- **Occurrences:** 1
- **Content-Type:** application/json

**Request Headers (sample):**
```
content-type: application/json
referer: https://us-east-1.signin.aws/
sec-ch-ua: "Google Chrome";v="149", "Chromium";v="149", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
```

**Request Body (redacted):**
```
{}
```

**Response:** HTTP 200
```
{"token":"<REDACTED>.<REDACTED>.MEQCIF5QNQWjFRaNO3MigpduonkxjKsoat35LA323rqaovOGAiAOZaAg3gXfSx_M7kfvGGA6LJM2QUpBVApkD9gdxqR9bw"}
```

---

## Appendix: Field Map for Worker Implementation

The table below maps each captured endpoint to the worker step that needs it. Fill in the exact field names from the captured request/response bodies above.

| Endpoint | Worker Step | Method | Required Fields (from capture) |
|----------|-------------|--------|-------------------------------|
| `GET /assets/locales/en/passwordPolicy.json` | password | GET | — |
| `GET /assets/locales/en/usernamePage.json` | name | GET | — |
| `POST /platform/user-event/send-event` | name | POST | `inputs`, `requestId` |
| `GET /token/whoAmI` | consent | GET | — |
| `POST /consent_details` | consent | POST | `deviceContextId`, `clientId`, `clientType`, `userSessionId` |
| `POST /token` | consent | POST |  |
| `POST /device_authorization/accept_user_code` | device_confirm | POST | `userCode`, `userSessionId` |
| `POST /device_authorization/associate_token` | device_confirm | POST | `deviceContext`, `userSessionId` |
| `GET /` | _unmapped_ | GET | — |
| `GET /assets/locales/en/createPasswordPage.json` | _unmapped_ | GET | — |
| `GET /assets/locales/en/legalFooter.json` | _unmapped_ | GET | — |
| `GET /dist/locales/en-US_5bbe19f56bb47a0809c324b77927d292.json` | _unmapped_ | GET | — |
| `GET /dist/locales/nav-en-US_254d2e9f8362a2975ed05b6e14fc7a38.json` | _unmapped_ | GET | — |
| `GET /login` | _unmapped_ | GET | — |
| `GET /platform/d-9067642ac7/signup` | _unmapped_ | GET | — |
| `POST /api/create-identity` | _unmapped_ | POST | — |
| `POST /api/get-app-context` | _unmapped_ | POST | — |
| `POST /api/get-config` | _unmapped_ | POST | — |
| `POST /api/send-otp` | _unmapped_ | POST | — |
| `POST /api/start` | _unmapped_ | POST | — |
| `POST /auth/sso-token` | _unmapped_ | POST | — |
| `POST /csds/collector/v1/events/batch` | _unmapped_ | POST | — |
| `POST /log` | _unmapped_ | POST | — |
| `POST /metrics/fingerprint` | _unmapped_ | POST | — |
| `POST /panoramaroute` | _unmapped_ | POST | — |
| `POST /platform/d-9067642ac7/api/execute` | _unmapped_ | POST | — |
| `POST /platform/d-9067642ac7/signup/api/execute` | _unmapped_ | POST | — |

> **Note for Task 6 (worker implementation):** The `_unmapped` rows above are endpoints that were hit during the capture session but don't obviously map to a known worker step. Review them and either assign to a step or note as noise.

