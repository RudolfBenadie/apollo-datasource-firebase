![npm](https://img.shields.io/npm/v/apollo-datasource-firebase?color=blue&style=plastic)


# apollo-datasource-firebase

Connect your GraphQL server to Google Firebase using DataSources.

## Firebase Data Source

### Install

```
yarn add apollo-datasource-firebase
```

or

```
npm i apollo-datasource-firebase --save
```

### Usage

Define a data source by extending the `FirebaseDataSource` class. You can then implement the queries and mutations that your resolvers require.

Create a configuration object or json file with the following format to initialise the Firebase and Firebase Admin APIs.

#### __firebaseConfig.json__
```javascript
{
  "firebaseOptions": {
    "apiKey": "<application-api-key>",
    "authDomain": "<project-id>.firebaseapp.com",
    "databaseURL": "https://<project-id>.firebaseio.com",
    "projectId": "<project-id>",
    "storageBucket": "<project-id>.appspot.com",
    "messagingSenderId": "<messaging-sender-id>",
    "appId": "<app-id>",
    "measurementId": "<measurement-id>"
  },
  "serviceAccount": {
    "type": "service_account",
    "project_id": "<project-id>",
    "private_key_id": "<private-key-id>",
    "private_key": "<private-key>",
    "client_email": "<service-account-email>",
    "client_id": "<client-id>",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "client-x509-cert-url"
  },
  "databaseURL": "https://<project-id>.firebaseio.com" 
}
```

#### __users.js__
```javascript
const FirebaseDataSource = require('apollo-datasource-firebase');
const firebaseConfig = require('./firebaseConfig.json');

class UsersAPI extends FirebaseDataSource {
  
  constructor() {
    super(firebaseConfig);
  }

  async retrievePageOfUsers(pageSize, pageToken) {
    var usersListResult = await this.getPageOfUsers({ pageSize, pageToken });
    return usersListResult;
  }

  async signUp( email, password ) {
    var user = await this.userSignUp({email, password});
    return user;
  }

  async signIn( email, password ) {
    return await this.userSignIn({email, password});
  }

}

module.exports = UsersAPI;

```
