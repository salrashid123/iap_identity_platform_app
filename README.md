# Identity Aware Proxy Authentication with Cloud Identity Platform

A couple weeks ago a i came across a particular configuration parameter in Google Cloud's [Identity Aware Proxy (IAP)](https://cloud.google.com/iap):  

* `access_settings.gcip_settings`: Use Identity Platform for authentication 

GCPIP is ofcourse [Google Cloud Identity Platform](https://cloud.google.com/identity-platform/docs/) but its inclusion into a config parameter for IAP suggested you could integrate identity platform tokens with IAP.  

I was intrigued because up until this time, IAP only allowed Google's first party auth system though.  What i mean by that is you had to startup with a google identity (user or serviceAccount) to access an app behind IAP (google being the 1st party here!).  

However, GCPIP allows for 3rd party identities and authentication systems for standard oauth2 providers (eg. `Yahoo`, `Facebook`),  bring your own `OIDC` (OpenId Connect) or `SAML` sample or just plain old username/password.  Why the integration of GCPIP and IAP was interesting was because these 3rd party identities didn't 'mean anything' to Google Cloud in the sense that you can use a user's that logged into GCPIP it to access (non-Firebases) APIs and services on GCP like invoke the Compute Engine API or`PubSub`.

In looking into this a bit more, i found the following link which described part of how to set this up (or rather, what to expect on the IAP side):

* [JWTs for external identities](https://cloud.google.com/iap/docs/signed-headers-howto#jwts_for_external_identities)

As with most things, i started to develop an application to help my understanding and to explore how GCPIP's 3rd party identities can be used to access an IAP protected site.

What this tutorial does is the following:

* Configure a simple web application using `Identity Platform's` SDK
* Configure Identity Platform to use `Email/Password` provider (you can use any, this is just to demo and easiest)
* Deploy an API application to AppEngine and allow CORS
* Enable IAP on AppEngine
* Configure IAP to use `3rd party` "Identity Platform" provided users

Once a user logs into your Identity Platform application, an API request using your `id_token` will be made to the appengine application.  Since the application is protected by IAP, it will check the tokens validity and allow it through. 

![images/arch.png](images/arch.png)

Just for reference

`IAP` is basically a super proxy inspired by Google's [BeyondCorp](https://cloud.google.com/beyondcorp/) that uses to provide user- and device-based authentication and authorization and not just a network perimeter (eg, VPN).  You use it to easily shield your web application to certain groups of users and perform [Context Aware Access Control](https://cloud.google.com/iap/docs/cloud-iap-context-aware-access-howto).

`Cloud Identity Platform` is basically Google Cloud's Customer Identity management solution similar to `Auth0` or `Okta`.  As with any CIAM solution, you can use it to manage user signup and authentication flows done though a variety of 3rd party ideneity providers.  

The SDK it provides allows you to easily perform user authentication for a visitor to your application by managing the oauth2 flows against a variety of providers like `Google`, `Facebook`, `Yahoo` and much more.

>> NOTE:  this tutorial is **NOT** supported by Google.  _caveat emptor_


### Limitations

This is justa POC, some limitations you need to know:
* IAP [Context Aware Access](https://cloud.google.com/context-aware-access/docs/overview) is not supported with 3rd party identities.


## Setup

Lets start, you'll clearly need a GCP project you can dispose of after this.  In my case, the projectName blow is `ip-iap-auth` 

Edit `/etc/hosts` and add an alias for the portal `app` site you will run locally

```
127.0.0.1 sp.providerdomain.com
```
We need to do this step since we will be running the Frontend Application on your laptop (ofcourse you're free to run it anywhere)

## Identity Platform

Now configure `Identity Platform` to use the basic `Email/Password`.  First change directory in this repo to `cd gcp_cicp/`

### Enable Identity Platform:  

Navigate to the cloud console for the project you are using and enable Identity Platfor:

* [https://console.cloud.google.com/marketplace/details/google-cloud-platform/customer-identity](https://console.cloud.google.com/marketplace/details/google-cloud-platform/customer-identity)


### Enable Email/Password

Once enabled, on the `Providers` section, use `Email/Password`  (again, you can use any provider; we're just using this for simplicity)

![images/1_ip_provider.png](images/1_ip_provider.png)


Select `setup details` on the top right and copy the configuration snippet


### Edit `templates/layout.html`

First we will need to configure the Identity Platform SDK to use your configuration:

Edit `layout.html` and replace the section below with your APIKey and authDomain.  For me, it was:

```xml
<script src="https://www.gstatic.com/firebasejs/7.8.1/firebase.js"></script>
<script>
  var config = {
    apiKey: "AIzaSyBFQhFQQsE-CzusiwfXDINvw8weTNszb30",
    authDomain: "ip-iap-auth.firebaseapp.com",
  };
  firebase.initializeApp(config);
</script>
```

###  Download key for firebase admin service account

The "server-side" of a the frontend application verifies an id_token after authentication so we need to download a service account private key fo your app.  You can read more about this step  here:

* [Verify ID tokens using the Firebase Admin SDK](https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_the_firebase_admin_sdk)

```bash
$ gcloud iam service-accounts list
NAME                                EMAIL                                                        DISABLED
firebase-adminsdk                   firebase-adminsdk-qfqza@ip-iap-auth.iam.gserviceaccount.com  False
App Engine default service account  ip-iap-auth@appspot.gserviceaccount.com                      False

$ gcloud iam service-accounts keys create  svc_account.json --iam-account=firebase-adminsdk-qfqza@ip-iap-auth.iam.gserviceaccount.com
```

### Edit main.py

Add in the name of your project into the following section:

This setting will make the API call back to an appengine application we will setup later

```python
@app.route('/portal', methods=["GET"])
def portal():
    app_location = "https://YOUR_PROJECT.appspot.com/user"
    return render_template('portal.html', app_location=app_location)
```

### Start Identity Platform application

The following commands will start the server-side of the "Frontend Application" (the Identity Platform enabled app)


```bash
virtualenv env
source env/bin/activate
pip install -r requirements.txt

python main.py
```

(i'm using python27 here and 3 later (i just didn't have time to migrate this)


## App Engine

Now deploy the appengine `API server`.  What the API server actually just does is echo's back the IAP parameters that get forwarded to it:

the `/user` endpoint is our "API":

```python
@app.route('/user')
def user():
  h = request.headers.get('X-Goog-Authenticated-User-Email')
  u = request.headers.get('X-Goog-Authenticated-User-ID')
  jwt =request.headers.get('x-goog-iap-jwt-assertion')

  resp = {
    'X-Goog-Authenticated-User-Email': h,
    'X-Goog-Authenticated-User-ID': u,
    'x-goog-iap-jwt-assertion': jwt
  }
  return jsonify(resp)
```

For more info, see:
* [Securing your app with IAP headers](https://cloud.google.com/iap/docs/signed-headers-howto#securing_iap_headers)


```bash
cd app_min/

python3 -m venv env
source env/bin/activate

pip3 install -r requirements.txt -t lib
deactivate
rm -rf env
```

We will use `version=1` and `us-central` as the zone as we will use this later for IAP's settings

```bash
$ gcloud app deploy  --version=1 .

(select 12- us-central)
```

## IAP

At this point the API server is deployed but is not protected by IAP...the next step enables that

### Enable IAP 

In the `Cloud Console > Security`  (follow prompts to configure consent screen).

Select `External` UserType.  Normally, if you asked for sensitive scopes during oauth, you will need to get whitelisted by google.  In our case, we don't really need this since we're going to use our own provider and no scopes are involved in the oauth2 sense.

Go back to IAP's configuration screen and select `Use External Identities for Authentication`: 

![images/enable_3rd_party_auth.png](images/enable_3rd_party_auth.png)


Specify the API key and the URL pointing back to our test application which we will run locally shortly:

In my case, it is (note, use `sp.providerdomain.com`...this is what this tutorial uses!)

```bash
https://sp.providerdomain.com:38080?apiKey=AIzaSyBFQhFQQsE-CzusiwfXDINvw8weTNszb30
```

So your configuration screen should look like the following:

![images/iap_configuration.png](images/iap_configuration.png)

Interms of APIcalls, this sets the default `GCPIP` settings in the api referred to in the first paragraph:

* [gcip_settings](https://cloud.google.com/iap/docs/reference/rest/v1/IapSettings#GcipSettings)

The `tenantIds[]` setting is set by default to the project level set of users (meaning all users in `Identity Platform`)

## Start Frontend Application

We're now ready to startup your "Frontend" application

```bash
cd gcp_cicp/
virtualenv env
source env/bin/activate
pip install -r requirements.txt

python main.py
```

Now goto `https://sp.providerdomain.com:38080/`

You should see the 'portal' page where you can login with a new email/password combo.  

Pick any user (`user1@somedomain.com`), and any password of length 6.

You should see a login success and a [Firebase id_token](https://firebase.google.com/docs/auth/users#auth_tokens) for the user in the console:

![images/options.png](images/options.png)

Which is good...but you should've also seen the API call back to the GAE application.

....but we didn't! :(
  
If you look at the actual http request/response, what we see is that the api call didn't even make it....why? `CORS`!


ok, so now we have to enable cors for appengine...its a bit complicated though:

## Enable CORS on appengine

ok, we need to enable cors by allowing the `OPTIONS` verb through

in a new window, setup some env-vars:

```bash
cd app_min

export ACCESS_TOKEN=`gcloud auth print-access-token`

export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER="$(gcloud projects describe $PROJECT_ID --format='get(projectNumber)')"
export SERVICE=default
export VERSION=1
```

then check if you can recall the default config for your appengine app and `version=1`

```
$ curl -s -H "Authorization: Bearer $ACCESS_TOKEN" https://iap.googleapis.com/v1/projects/$PROJECT_ID/iap_web/appengine-$PROJECT_ID/services/$SERVICE/versions/$VERSION:iapSettings
{
  "name": "projects/43866125167/iap_web/appengine-ip-iap-auth/services/default/versions/1"
}
```

Now apply the PATH verb to enable `corsSettings: true`

```bash
curl -v -X PATCH  -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS_TOKEN" --data "{ \"name\": \"projects/$PROJECT_NUMBER/iap_web/appengine-$PROJECT_ID/services/default/versions/1\", \"accessSettings\": {    \"corsSettings\": {      \"allowHttpOptions\": true } } }"  https://iap.googleapis.com/v1/projects/$PROJECT_NUMBER/iap_web/appengine-$PROJECT_ID/services/$SERVICE/versions/$VERSION:iapSettings
```

You should see a basic response back confirming:

```json
{
  "name": "projects/43866125167/iap_web/appengine-ip-iap-auth/services/default/versions/1",
  "accessSettings": {
    "corsSettings": {
      "allowHttpOptions": true
    }
  }
}
```

## Retest Frontend application

Now refresh the frontend app and login.  You should now see both the [Identity Platform id_token](https://firebase.google.com/docs/auth/users#auth_tokens) in the first box as well as the API response in the second box

![images/cors_auth.png](images/cors_auth.png)


in terms of headers, you should see the logs make the `OPTIONS` calls succeed as well as a `200 ok` from the GAE API server

![images/gae_logs.png](images/gae_log.png)

You can take the `FirebaseID Tokens`  and decode it at [jwt.io](jwt.io)

You should see something like:

```json
{
  "name": "user1 user1",
  "iss": "https://securetoken.google.com/ip-iap-auth",
  "aud": "ip-iap-auth",
  "auth_time": 1581265941,
  "user_id": "7TyRH07q7tW01IDlTVnOu2MGHKf1",
  "sub": "7TyRH07q7tW01IDlTVnOu2MGHKf1",
  "iat": 1581265970,
  "exp": 1581269570,
  "email": "user1@somedomain.com",
  "email_verified": false,
  "firebase": {
    "identities": {
      "email": [
        "user1@somedomain.com"
      ]
    },
    "sign_in_provider": "password"
  }
}
```

You can also take the IAP jwt that was echo'd back by the GAE "api server" which you can also decode

```json
{
  "aud": "/projects/43866125167/apps/ip-iap-auth",
  "email": "securetoken.google.com/ip-iap-auth:user1@somedomain.com",
  "exp": 1581266570,
  "gcip": {
    "auth_time": 1581265941,
    "email": "user1@somedomain.com",
    "email_verified": false,
    "firebase": {
      "identities": {
        "email": [
          "user1@somedomain.com"
        ]
      },
      "sign_in_provider": "password"
    },
    "name": "user1 user1",
    "sub": "7TyRH07q7tW01IDlTVnOu2MGHKf1",
    "user_id": "7TyRH07q7tW01IDlTVnOu2MGHKf1"
  },
  "iat": 1581265970,
  "iss": "https://cloud.google.com/iap",
  "sub": "securetoken.google.com/ip-iap-auth:7TyRH07q7tW01IDlTVnOu2MGHKf1"
}
```

>> Note: you do not need to send this token back from IAP...this is just for a demo


## Multi-Tenancy

So far the users that get provisioned in identity platform is just for the 'root' userbase.   However, Identity Platform now supports multi-tenancy which you can also enable and use.  For more info, see

* [Identity Platform multi-tenancy](https://cloud.google.com/identity-platform/docs/multi-tenancy)
* [Authenticating with multi-tenancy](https://cloud.google.com/identity-platform/docs/multi-tenancy-authentication)

###  Configure Tenants

If you want to configure multi tenancy, create a tenant and note the `TenantID`
 
![images/tenant-enable.png](images/tenant-enable.png)

For me it was: `tenant1-jc8mz`

Edit `templates/index.html` and add in the tenantId()

```javascript
              <div class="mdl-textfield mdl-js-textfield mdl-textfield--floating-label">
                  <select class="mdl-textfield__input" id="tenant" name="tenant">
                    <option></option>
                    <option value="tenant1-jc8mz">tenant1-jc8mz</option>
                  </select>
                  <label class="mdl-textfield__label" for="tenant">Tenant</label>     
              </div>
```

Then enable the `Email/Password` provider (each tenant can have different config so we have to enable it here):

![images/tenant-provider-config.png](images/tenant-provider-config.png)

### Configure IAP to accept tenant's authenticators

Go back to IAP config screen and select the tenant for auth (not the project identities):

![images/iap_tenant.png](images/iap_tenant.png)

### Refresh 'Frontend' and login

Reload the frontend application and select the tenant context:

![images/tenant-login.png](images/tenant-login.png)

Create a new user and perform the login flow.

eg: `tenantuser1@otherdomain.com`

### View JWT for tenant

You should again see the Identity Platform JWT which you can decode:

```json
{
  "name": "tenant user1",
  "iss": "https://securetoken.google.com/ip-iap-auth",
  "aud": "ip-iap-auth",
  "auth_time": 1581275995,
  "user_id": "mrSq8EtNFwcBAvJpRCDRuqMRG433",
  "sub": "mrSq8EtNFwcBAvJpRCDRuqMRG433",
  "iat": 1581275996,
  "exp": 1581279596,
  "email": "tenantuser1@otherdomain.com",
  "email_verified": false,
  "firebase": {
    "identities": {
      "email": [
        "tenantuser1@otherdomain.com"
      ]
    },
    "sign_in_provider": "password",
    "tenant": "tenant1-jc8mz"
  }
}
```

As well as the internal IAP JWT:

```json
{
  "aud": "/projects/43866125167/apps/ip-iap-auth",
  "email": "securetoken.google.com/ip-iap-auth/tenant1-jc8mz:tenantuser1@otherdomain.com",
  "exp": 1581276597,
  "gcip": {
    "auth_time": 1581275995,
    "email": "tenantuser1@otherdomain.com",
    "email_verified": false,
    "firebase": {
      "identities": {
        "email": [
          "tenantuser1@otherdomain.com"
        ]
      },
      "sign_in_provider": "password",
      "tenant": "tenant1-jc8mz"
    },
    "name": "tenant user1",
    "sub": "mrSq8EtNFwcBAvJpRCDRuqMRG433",
    "user_id": "mrSq8EtNFwcBAvJpRCDRuqMRG433"
  },
  "iat": 1581275997,
  "iss": "https://cloud.google.com/iap",
  "sub": "securetoken.google.com/ip-iap-auth/tenant1-jc8mz:mrSq8EtNFwcBAvJpRCDRuqMRG433"
}
```

Thats i!...you'v now used identity platform 3rd party identities against an IAP protected app.

In this example, the backend IAP protected app is on appengine but you are free to deploy IAP against an [onprem application too](https://cloud.google.com/iap/docs/enabling-on-prem-howto)!!


### References

* [Getting started with Identity Platform](https://cloud.google.com/blog/products/identity-security/getting-started-with-identity-platform)
* [Single Page webapp using GKE, App Engine, Google Cloud Endpoints and Identity Aware Proxy](https://github.com/salrashid123/iap_endpoints_app)


